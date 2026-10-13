//! The CSV reader: one file is one object. Describe reads the header and
//! samples, Page reads rows by offset, and Delta is the file's hash. The
//! parser follows RFC 4180 with a sniffed delimiter, so an export from a
//! spreadsheet, a bank or a billing system reads without a setting.

use crate::reader::{
    guess_type, Cursor, Delta, Description, FieldDescription, ObjectInfo, Page, Reader,
    ReaderError, Row,
};
use muniment_core::sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The largest file the reader opens. A larger export is split first.
pub const CSV_BYTE_CAP: u64 = 64 * 1024 * 1024;
/// The most cells the reader holds for one file, counting the cells a short
/// row gains when it is padded to the header's width. A file of delimiters
/// alone would otherwise build one string per byte.
pub const CSV_CELL_CAP: usize = 4_000_000;
/// How many rows Describe samples for types and examples.
const SAMPLE_ROWS: usize = 200;
/// How many distinct examples a field carries.
const SAMPLES_PER_FIELD: usize = 3;
/// The longest sample text Describe returns.
const SAMPLE_CHARS: usize = 80;

pub struct CsvReader {
    path: PathBuf,
    cell_cap: usize,
}

struct Parsed {
    header: Vec<String>,
    rows: Vec<Vec<String>>,
    hash: String,
    bytes: u64,
}

impl CsvReader {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            cell_cap: CSV_CELL_CAP,
        }
    }

    /// A reader with a smaller cell cap, so a test reaches the cap with a small file.
    #[cfg(test)]
    fn with_cell_cap(path: impl AsRef<Path>, cell_cap: usize) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            cell_cap,
        }
    }

    fn label(&self) -> String {
        self.path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.path.to_string_lossy().into_owned())
    }

    fn check_object(&self, object: &str) -> Result<(), ReaderError> {
        if object == self.path.to_string_lossy() {
            Ok(())
        } else {
            Err(ReaderError::UnknownObject(object.to_owned()))
        }
    }

    fn read(&self) -> Result<Parsed, ReaderError> {
        let metadata = fs::metadata(&self.path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ReaderError::UnknownObject(self.path.to_string_lossy().into_owned())
            } else {
                ReaderError::Unreadable(error.to_string())
            }
        })?;
        if !metadata.is_file() {
            return Err(ReaderError::Unreadable("it is not a file".to_owned()));
        }
        if metadata.len() > CSV_BYTE_CAP {
            return Err(ReaderError::TooLarge {
                bytes: metadata.len(),
                cap: CSV_BYTE_CAP,
            });
        }
        let bytes =
            fs::read(&self.path).map_err(|error| ReaderError::Unreadable(error.to_string()))?;
        let hash = hex_lower(&Sha256::digest(&bytes));
        let text = String::from_utf8_lossy(&bytes);
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        let mut records = parse_csv(text, sniff_delimiter(text), self.cell_cap)?;
        if records.is_empty() {
            return Err(ReaderError::Malformed(
                "the file has no header row".to_owned(),
            ));
        }
        let header = records.remove(0);
        let width = header.len();
        let mut rows: Vec<Vec<String>> = records
            .into_iter()
            .filter(|record| record.iter().any(|cell| !cell.trim().is_empty()))
            .collect();
        let padded_cells = rows
            .len()
            .checked_add(1)
            .and_then(|records| records.checked_mul(width));
        if !matches!(padded_cells, Some(cells) if cells <= self.cell_cap) {
            return Err(too_many_cells(self.cell_cap));
        }
        let header = header_names(header);
        for record in &mut rows {
            record.resize(width, String::new());
        }
        Ok(Parsed {
            header,
            rows,
            hash,
            bytes: metadata.len(),
        })
    }
}

impl Reader for CsvReader {
    fn objects(&self) -> Result<Vec<ObjectInfo>, ReaderError> {
        Ok(vec![ObjectInfo {
            name: self.path.to_string_lossy().into_owned(),
            label: self.label(),
        }])
    }

    fn describe(&self, object: &str) -> Result<Description, ReaderError> {
        self.check_object(object)?;
        let parsed = self.read()?;
        let fields = parsed
            .header
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let column = parsed
                    .rows
                    .iter()
                    .take(SAMPLE_ROWS)
                    .map(|row| row[index].as_str());
                let mut samples = Vec::new();
                let mut seen = BTreeSet::new();
                for value in column.clone() {
                    let value = value.trim();
                    if value.is_empty() || !seen.insert(value) {
                        continue;
                    }
                    samples.push(value.chars().take(SAMPLE_CHARS).collect());
                    if samples.len() == SAMPLES_PER_FIELD {
                        break;
                    }
                }
                FieldDescription {
                    name: name.clone(),
                    guess: guess_type(column),
                    samples,
                    filled: parsed
                        .rows
                        .iter()
                        .filter(|row| !row[index].trim().is_empty())
                        .count(),
                }
            })
            .collect();
        Ok(Description {
            source: crate::reader::CSV_SOURCE.to_owned(),
            object: object.to_owned(),
            label: self.label(),
            fields,
            rows: parsed.rows.len(),
            bytes: parsed.bytes,
            hash: parsed.hash,
            counted: true,
        })
    }

    fn page(
        &self,
        object: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<Page, ReaderError> {
        self.check_object(object)?;
        let parsed = self.read()?;
        let offset = cursor
            .map_or(0, |cursor| cursor.offset)
            .min(parsed.rows.len());
        let end = offset.saturating_add(limit.max(1)).min(parsed.rows.len());
        let rows = parsed.rows[offset..end]
            .iter()
            .map(|record| {
                parsed
                    .header
                    .iter()
                    .cloned()
                    .zip(record.iter().cloned())
                    .collect::<Row>()
            })
            .collect();
        Ok(Page {
            rows,
            offset,
            total: parsed.rows.len(),
            next: (end < parsed.rows.len()).then(|| Cursor {
                offset: end,
                hash: parsed.hash.clone(),
                token: None,
            }),
            hash: parsed.hash,
            counted: true,
        })
    }

    fn delta(&self, object: &str, cursor: &Cursor) -> Result<Delta, ReaderError> {
        self.check_object(object)?;
        match self.read() {
            Ok(parsed) if parsed.hash == cursor.hash => Ok(Delta::Unchanged),
            Ok(parsed) => Ok(Delta::Changed { hash: parsed.hash }),
            Err(ReaderError::UnknownObject(_)) => Ok(Delta::Gone),
            Err(error) => Err(error),
        }
    }
}

/// The delimiter the header line uses most: a comma, else a semicolon or a
/// tab when the header holds one of those and no comma.
fn sniff_delimiter(text: &str) -> char {
    let header = text.lines().next().unwrap_or_default();
    let mut best = (0_usize, ',');
    for candidate in [',', ';', '\t', '|'] {
        let count = header.matches(candidate).count();
        if count > best.0 {
            best = (count, candidate);
        }
    }
    best.1
}

/// A header cell that is empty becomes `column_<n>`, and a repeated name
/// gains a suffix, so every field has one name a mapping can point at.
fn header_names(header: Vec<String>) -> Vec<String> {
    let mut names: Vec<String> = Vec::with_capacity(header.len());
    let mut taken = std::collections::HashSet::with_capacity(header.len());
    // The next suffix to try for each base. A taken name never frees, so the search
    // resumes where it stopped, and a header of one repeated name stays linear.
    let mut next_suffix = std::collections::HashMap::new();
    for (index, cell) in header.into_iter().enumerate() {
        let base = cell.trim().to_owned();
        let base = if base.is_empty() {
            format!("column_{}", index + 1)
        } else {
            base
        };
        let mut name = base.clone();
        if taken.contains(&name) {
            let suffix = next_suffix.entry(base.clone()).or_insert(2_usize);
            loop {
                name = format!("{base}_{suffix}");
                *suffix += 1;
                if !taken.contains(&name) {
                    break;
                }
            }
        }
        taken.insert(name.clone());
        names.push(name);
    }
    names
}

fn too_many_cells(cell_cap: usize) -> ReaderError {
    ReaderError::Source {
        code: "too_large".to_owned(),
        message: format!(
            "The file holds more than {cell_cap} cells and the reader stops there. Split the export first."
        ),
    }
}

/// RFC 4180: fields split on the delimiter, a quoted field keeps delimiters
/// and line breaks, and a doubled quote inside it is one quote. A record ends
/// at a line feed outside quotes, with or without a carriage return.
/// The parse fails once it holds more than `cell_cap` cells.
pub fn parse_csv(
    text: &str,
    delimiter: char,
    cell_cap: usize,
) -> Result<Vec<Vec<String>>, ReaderError> {
    let mut cells = 0_usize;
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut after_closing_quote = false;
    let mut chars = text.chars().peekable();
    let mut line = 1_usize;
    while let Some(character) = chars.next() {
        if quoted {
            match character {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => {
                    quoted = false;
                    after_closing_quote = true;
                }
                '\n' => {
                    line += 1;
                    field.push(character);
                }
                _ => field.push(character),
            }
            continue;
        }
        match character {
            '"' if field.is_empty() && !after_closing_quote => quoted = true,
            '"' => {
                return Err(ReaderError::Malformed(format!(
                    "a quote sits inside an unquoted field on line {line}"
                )))
            }
            '\r' if chars.peek() == Some(&'\n') => {}
            character if character == delimiter => {
                cells += 1;
                if cells > cell_cap {
                    return Err(too_many_cells(cell_cap));
                }
                record.push(std::mem::take(&mut field));
                after_closing_quote = false;
            }
            '\n' => {
                line += 1;
                cells += 1;
                if cells > cell_cap {
                    return Err(too_many_cells(cell_cap));
                }
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
                after_closing_quote = false;
            }
            _ if after_closing_quote && !character.is_whitespace() => {
                return Err(ReaderError::Malformed(format!(
                    "text follows a closing quote on line {line}"
                )))
            }
            _ if after_closing_quote => {}
            _ => field.push(character),
        }
    }
    if quoted {
        return Err(ReaderError::Malformed(format!(
            "a quoted field opened on line {line} never closes"
        )));
    }
    if !field.is_empty() || !record.is_empty() {
        if cells >= cell_cap {
            return Err(too_many_cells(cell_cap));
        }
        record.push(field);
        records.push(record);
    }
    Ok(records)
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary(label: &str, text: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "muniment-reader-csv-{label}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("customers.csv");
        fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn parses_quotes_line_breaks_and_a_sniffed_delimiter() {
        let records = parse_csv(
            "name,domain,\"note, long\"\r\n\"Northwind, Inc.\",northwind.example,\"line one\nline two\"\nContoso,contoso.example,\"say \"\"hi\"\"\"\n",
            ',',
            CSV_CELL_CAP,
        )
        .unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0], vec!["name", "domain", "note, long"]);
        assert_eq!(records[1][0], "Northwind, Inc.");
        assert_eq!(records[1][2], "line one\nline two");
        assert_eq!(records[2][2], "say \"hi\"");
        assert_eq!(sniff_delimiter("a;b;c\n1;2;3"), ';');
        assert_eq!(sniff_delimiter("a\tb\n1\t2"), '\t');
        assert_eq!(sniff_delimiter("a,b;c\n"), ',');
        assert_eq!(sniff_delimiter("single\n"), ',');
        assert_eq!(
            header_names(vec!["a".into(), "".into(), "a".into(), " b ".into()]),
            vec!["a", "column_2", "a_2", "b"]
        );
        assert!(parse_csv("a,b\n\"open,1\n", ',', CSV_CELL_CAP)
            .unwrap_err()
            .to_string()
            .contains("never closes"));
        assert!(parse_csv("a,b\nx\"y,1\n", ',', CSV_CELL_CAP).is_err());
        assert!(parse_csv("a,b\n\"x\"y,1\n", ',', CSV_CELL_CAP).is_err());
    }

    #[test]
    fn stops_at_the_cell_cap() {
        assert_eq!(parse_csv("a,b\n1,2\n", ',', 4).unwrap().len(), 2);
        for text in ["a,b\n1,2\n3", "a,b\n1,2,3\n", ",,,,,"] {
            let error = parse_csv(text, ',', 4).unwrap_err();
            assert_eq!(error.code(), "too_large");
            assert!(error.to_string().contains("more than 4 cells"));
        }

        const CAP: usize = 1_000;
        let commas = temporary("commas", &",".repeat(CAP + 1));
        let object = commas.to_string_lossy().into_owned();
        let error = CsvReader::with_cell_cap(&commas, CAP)
            .describe(&object)
            .unwrap_err();
        assert_eq!(error.code(), "too_large");

        // A wide header pads every short row to its width, and the padding counts.
        let wide = temporary("wide", &format!("{}\nx\ny\n", ",".repeat(CAP / 2)));
        let object = wide.to_string_lossy().into_owned();
        let error = CsvReader::with_cell_cap(&wide, CAP)
            .describe(&object)
            .unwrap_err();
        assert_eq!(error.code(), "too_large");
        assert!(CsvReader::with_cell_cap(&wide, CAP * 2)
            .describe(&object)
            .is_ok());

        // The public reader and parse use the production cap.
        assert_eq!(CsvReader::new(&wide).cell_cap, CSV_CELL_CAP);
        assert!(parse_csv(&",".repeat(CAP), ',', CSV_CELL_CAP).is_ok());
    }

    #[test]
    fn names_a_header_of_one_repeated_name_in_linear_time() {
        let names = header_names(vec!["a".into(); 20_000]);
        assert_eq!(names[0], "a");
        assert_eq!(names[1], "a_2");
        assert_eq!(names[19_999], "a_20000");
        assert_eq!(
            header_names(vec!["a".into(), "a_3".into(), "a".into(), "a".into()]),
            ["a", "a_3", "a_2", "a_4"]
        );
    }

    #[test]
    fn describes_pages_and_detects_a_changed_file() {
        let path = temporary(
            "describe",
            "\u{feff}Company,Website,Email,Employees,Since,Active\nNorthwind,https://www.northwind.example,ann@northwind.example,120,2020-01-15,yes\nContoso,contoso.example,bob@contoso.example,40,2021-06-01,no\n,,,,,\nFabrikam,fabrikam.example,,7,2019-12-31,yes\n",
        );
        let object = path.to_string_lossy().into_owned();
        let reader = CsvReader::new(&path);
        assert_eq!(reader.objects().unwrap()[0].label, "customers.csv");
        let description = reader.describe(&object).unwrap();
        assert_eq!(description.rows, 3);
        assert_eq!(description.label, "customers.csv");
        let names: Vec<&str> = description
            .fields
            .iter()
            .map(|field| field.name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "Company",
                "Website",
                "Email",
                "Employees",
                "Since",
                "Active"
            ]
        );
        let guesses: Vec<&str> = description
            .fields
            .iter()
            .map(|field| field.guess.as_str())
            .collect();
        assert_eq!(
            guesses,
            ["string", "domain", "email", "integer", "date", "boolean"]
        );
        assert_eq!(description.fields[2].filled, 2);
        assert_eq!(
            description.fields[0].samples,
            ["Northwind", "Contoso", "Fabrikam"]
        );

        let first = reader.page(&object, None, 2).unwrap();
        assert_eq!(first.rows.len(), 2);
        assert_eq!(first.total, 3);
        assert_eq!(first.rows[0]["Company"], "Northwind");
        let cursor = first.next.clone().unwrap();
        assert_eq!(cursor.offset, 2);
        let second = reader.page(&object, Some(&cursor), 2).unwrap();
        assert_eq!(second.rows.len(), 1);
        assert_eq!(second.rows[0]["Company"], "Fabrikam");
        assert!(second.next.is_none());
        assert_eq!(reader.delta(&object, &cursor).unwrap(), Delta::Unchanged);

        fs::write(&path, "Company\nOther\n").unwrap();
        assert!(matches!(
            reader.delta(&object, &cursor).unwrap(),
            Delta::Changed { .. }
        ));
        fs::remove_file(&path).unwrap();
        assert_eq!(reader.delta(&object, &cursor).unwrap(), Delta::Gone);
        assert_eq!(
            reader.describe(&object).unwrap_err().code(),
            "unknown_object"
        );
        assert_eq!(
            reader.describe("/elsewhere.csv").unwrap_err().code(),
            "unknown_object"
        );
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn refuses_an_empty_file_and_a_directory() {
        let path = temporary("empty", "");
        let object = path.to_string_lossy().into_owned();
        assert_eq!(
            CsvReader::new(&path).describe(&object).unwrap_err().code(),
            "malformed"
        );
        let directory = path.parent().unwrap().to_path_buf();
        let object = directory.to_string_lossy().into_owned();
        assert_eq!(
            CsvReader::new(&directory)
                .describe(&object)
                .unwrap_err()
                .code(),
            "unreadable"
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
