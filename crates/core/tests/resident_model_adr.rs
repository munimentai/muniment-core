//! Keeps ADR 0017's pinned resident-model table and the compiled
//! `RESIDENT_MODEL` descriptor byte-for-byte identical.
//!
//! The shipped resident model once changed without its decision record — ADR
//! 0003 still pinned a Gemma GGUF while the code verified and served a Qwen
//! one — so the record and the descriptor are compared mechanically instead of
//! by review discipline. Editing either side alone fails this test.

use std::path::{Path, PathBuf};

use muniment_core::llama::RESIDENT_MODEL;

/// Descriptor fields the ADR must pin, in descriptor declaration order.
const PINNED_FIELDS: [&str; 7] = [
    "source_url",
    "license",
    "filename",
    "byte_size",
    "sha256",
    "alias",
    "context_tokens",
];

/// Located by ADR number rather than by full filename, so renaming the record
/// cannot silently orphan this guard.
fn resident_model_adr() -> PathBuf {
    let decisions = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/decisions");
    let mut found: Vec<PathBuf> = std::fs::read_dir(&decisions)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", decisions.display()))
        .map(|entry| {
            entry
                .expect("docs/decisions entries must be readable")
                .path()
        })
        .filter(|path| {
            matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some(name) if name.starts_with("0017-") && name.ends_with(".md")
            )
        })
        .collect();
    found.sort();
    assert_eq!(
        found.len(),
        1,
        "expected exactly one docs/decisions/0017-*.md pinning the resident model, found {found:?}"
    );
    found.remove(0)
}

/// Returns the `| `field` | `value` |` rows naming a pinned descriptor field,
/// in document order. Rows of any other shape are ignored so the ADR may carry
/// unrelated tables, but a pinned field whose value is not a single code span
/// is a malformed pin rather than a row to skip.
fn pinned_rows(markdown: &str) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    for line in markdown.lines() {
        let Some(inner) = line
            .trim()
            .strip_prefix('|')
            .and_then(|row| row.strip_suffix('|'))
        else {
            continue;
        };
        let cells: Vec<&str> = inner.split('|').map(str::trim).collect();
        if cells.len() != 2 {
            continue;
        }
        let Some(field) = code_span(cells[0]) else {
            continue;
        };
        if !PINNED_FIELDS.contains(&field) {
            continue;
        }
        let value = code_span(cells[1]).unwrap_or_else(|| {
            panic!(
                "the pinned value for `{field}` must be one code span, found {:?}",
                cells[1]
            )
        });
        rows.push((field.to_owned(), value.to_owned()));
    }
    rows
}

fn code_span(cell: &str) -> Option<&str> {
    let inner = cell.strip_prefix('`')?.strip_suffix('`')?;
    (!inner.is_empty() && !inner.contains('`')).then_some(inner)
}

/// Renders a number the way the descriptor literal spells it, so the ADR and
/// the Rust source read identically.
fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.char_indices() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push('_');
        }
        grouped.push(digit);
    }
    grouped
}

#[test]
fn adr_0017_pins_the_compiled_resident_model_descriptor() {
    let path = resident_model_adr();
    let markdown = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()));

    let rows = pinned_rows(&markdown);
    let fields: Vec<&str> = rows.iter().map(|(field, _)| field.as_str()).collect();
    assert_eq!(
        fields,
        PINNED_FIELDS,
        "{} must pin every RESIDENT_MODEL field exactly once, in descriptor order",
        path.display()
    );

    let descriptor = [
        ("source_url", RESIDENT_MODEL.source_url.to_owned()),
        ("license", RESIDENT_MODEL.license.to_owned()),
        ("filename", RESIDENT_MODEL.filename.to_owned()),
        ("byte_size", grouped(RESIDENT_MODEL.byte_size)),
        ("sha256", RESIDENT_MODEL.sha256.to_owned()),
        ("alias", RESIDENT_MODEL.alias.to_owned()),
        (
            "context_tokens",
            grouped(u64::from(RESIDENT_MODEL.context_tokens)),
        ),
    ];

    for ((field, pinned), (_, compiled)) in rows.iter().zip(descriptor.iter()) {
        assert_eq!(
            pinned,
            compiled,
            "{} pins `{field}` as `{pinned}`, but the compiled RESIDENT_MODEL.{field} is \
             `{compiled}`; the decision record and the descriptor must change together",
            path.display()
        );
    }
}
