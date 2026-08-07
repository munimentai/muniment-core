use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

// Each entry must name the test and constant, for example
// ("deadline_uses_the_production_contract", "REQUEST_TIMEOUT").
const DELIBERATE_EXCEPTIONS: &[(&str, &str)] = &[("allowed_reference", "DEFAULT_TIMEOUT")];

#[test]
fn test_modules_do_not_inherit_production_timeout_constants() {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let violations = scan_tree(&source_root);
    assert!(
        violations.is_empty(),
        "test modules reference production timeout constants:\n{}",
        violations.join("\n")
    );
}

#[test]
fn guard_fixture_detects_a_production_timeout_reference() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/timeout_guard/references_constant.rs");
    let violations = scan_file(&fixture);
    assert_eq!(violations.len(), 1, "{violations:#?}");
    assert!(violations[0].contains("DEFAULT_TIMEOUT"));
    assert!(violations[0].contains("inherits_the_timeout"));
}

#[test]
fn guard_checks_references_after_an_allowed_reference() {
    let fixture = fixture("allowed_then_forbidden.rs");
    let violations = scan_file(&fixture);
    assert_eq!(violations.len(), 1, "{violations:#?}");
    assert!(violations[0].contains("forbidden_reference"));
}

#[test]
fn guard_finds_constants_declared_after_a_test_module() {
    let fixture = fixture("constant_after_test_module.rs");
    let violations = scan_file(&fixture);
    assert_eq!(violations.len(), 1, "{violations:#?}");
    assert!(violations[0].contains("LATE_TIMEOUT"));
}

#[test]
fn guard_checks_each_test_module() {
    let fixture = fixture("multiple_test_modules.rs");
    let violations = scan_file(&fixture);
    assert_eq!(violations.len(), 2, "{violations:#?}");
    assert!(violations[0].contains("first_reference"));
    assert!(violations[1].contains("second_reference"));
}

#[test]
fn guard_ignores_braces_inside_strings() {
    let fixture = fixture("string_brace_before_reference.rs");
    let violations = scan_file(&fixture);
    assert_eq!(violations.len(), 1, "{violations:#?}");
    assert!(violations[0].contains("reference_after_string_brace"));
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/timeout_guard")
        .join(name)
}

fn scan_tree(root: &Path) -> Vec<String> {
    let mut files = Vec::new();
    collect_rust_files(root, &mut files);
    files.sort();
    let constants: BTreeSet<String> = files
        .iter()
        .flat_map(|path| production_timeout_constants(&fs::read_to_string(path).unwrap()))
        .collect();
    files
        .into_iter()
        .flat_map(|path| scan_file_for_constants(&path, &constants))
        .collect()
}

fn collect_rust_files(root: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

fn scan_file(path: &Path) -> Vec<String> {
    let source = fs::read_to_string(path).unwrap();
    let constants = production_timeout_constants(&source);
    scan_source(path, &source, &constants)
}

fn scan_file_for_constants(path: &Path, constants: &BTreeSet<String>) -> Vec<String> {
    let source = fs::read_to_string(path).unwrap();
    scan_source(path, &source, constants)
}

fn scan_source(path: &Path, source: &str, constants: &BTreeSet<String>) -> Vec<String> {
    if constants.is_empty() {
        return Vec::new();
    }

    let lines: Vec<_> = source.lines().collect();
    let mut violations = Vec::new();
    for (start, end) in test_modules(&lines) {
        for constant in constants {
            for (offset, line) in lines[start..end].iter().enumerate() {
                let reference_line = start + offset;
                let test =
                    enclosing_test_name(&lines, start, reference_line).unwrap_or("unknown_test");
                for _ in identifier_occurrences(line, constant) {
                    if !DELIBERATE_EXCEPTIONS.contains(&(test, constant.as_str())) {
                        violations.push(format!(
                            "{}:{}: {test} references {constant}",
                            path.display(),
                            reference_line + 1
                        ));
                    }
                }
            }
        }
    }
    violations
}

fn production_timeout_constants(source: &str) -> BTreeSet<String> {
    let lines: Vec<_> = source.lines().collect();
    let test_modules = test_modules(&lines);
    lines
        .iter()
        .enumerate()
        .filter(|(line, _)| {
            !test_modules
                .iter()
                .any(|(start, end)| start <= line && line < end)
        })
        .map(|(_, line)| *line)
        .filter_map(|line| {
            let line = line.trim_start();
            let declaration = line
                .strip_prefix("const ")
                .or_else(|| line.strip_prefix("pub const "))
                .or_else(|| line.strip_prefix("pub(crate) const "))?;
            let name = declaration.split([':', ' ']).next()?;
            (name.contains("_TIMEOUT") || name.contains("_DEADLINE")).then(|| name.to_owned())
        })
        .collect()
}

fn test_modules(lines: &[&str]) -> Vec<(usize, usize)> {
    let brace_changes = code_brace_changes(lines);
    let mut modules = Vec::new();
    let mut line = 0;
    while line < lines.len() {
        if lines[line].trim() != "#[cfg(test)]" {
            line += 1;
            continue;
        }
        let Some(module_line) =
            (line + 1..lines.len()).find(|index| !lines[*index].trim().is_empty())
        else {
            return modules;
        };
        if !lines[module_line].trim_start().starts_with("mod ") {
            line = module_line + 1;
            continue;
        }
        let mut depth = 0_i32;
        let mut saw_open = false;
        let mut end = module_line;
        for (index, (change, has_open)) in brace_changes.iter().enumerate().skip(module_line) {
            saw_open |= has_open;
            depth += change;
            end = index + 1;
            if saw_open && depth == 0 {
                break;
            }
        }
        modules.push((module_line, end));
        line = end;
    }
    modules
}

#[derive(Clone, Copy)]
enum LexState {
    Code,
    String,
    Character,
    RawString(usize),
    BlockComment(usize),
}

fn code_brace_changes(lines: &[&str]) -> Vec<(i32, bool)> {
    let mut state = LexState::Code;
    lines
        .iter()
        .map(|line| code_brace_change(line.as_bytes(), &mut state))
        .collect()
}

fn code_brace_change(line: &[u8], state: &mut LexState) -> (i32, bool) {
    let mut depth = 0;
    let mut has_open = false;
    let mut index = 0;
    while index < line.len() {
        match *state {
            LexState::Code => match line[index] {
                b'/' if line.get(index + 1) == Some(&b'/') => break,
                b'/' if line.get(index + 1) == Some(&b'*') => {
                    *state = LexState::BlockComment(1);
                    index += 2;
                }
                b'b' if line.get(index + 1) == Some(&b'"') => {
                    *state = LexState::String;
                    index += 2;
                }
                b'b' if line.get(index + 1) == Some(&b'\'') => {
                    *state = LexState::Character;
                    index += 2;
                }
                b'r' | b'b' => {
                    if let Some((hashes, content_start)) = raw_string_start(line, index) {
                        *state = LexState::RawString(hashes);
                        index = content_start;
                    } else {
                        index += 1;
                    }
                }
                b'"' => {
                    *state = LexState::String;
                    index += 1;
                }
                b'\'' if character_literal_end(line, index).is_some() => {
                    *state = LexState::Character;
                    index += 1;
                }
                b'{' => {
                    depth += 1;
                    has_open = true;
                    index += 1;
                }
                b'}' => {
                    depth -= 1;
                    index += 1;
                }
                _ => index += 1,
            },
            LexState::String | LexState::Character => {
                let delimiter = if matches!(*state, LexState::String) {
                    b'"'
                } else {
                    b'\''
                };
                match line[index] {
                    b'\\' => index += 2,
                    byte if byte == delimiter => {
                        *state = LexState::Code;
                        index += 1;
                    }
                    _ => index += 1,
                }
            }
            LexState::RawString(hashes) => {
                if raw_string_ends_at(line, index, hashes) {
                    *state = LexState::Code;
                    index += hashes + 1;
                } else {
                    index += 1;
                }
            }
            LexState::BlockComment(nesting) => {
                if line.get(index..index + 2) == Some(b"/*") {
                    *state = LexState::BlockComment(nesting + 1);
                    index += 2;
                } else if line.get(index..index + 2) == Some(b"*/") {
                    *state = if nesting == 1 {
                        LexState::Code
                    } else {
                        LexState::BlockComment(nesting - 1)
                    };
                    index += 2;
                } else {
                    index += 1;
                }
            }
        }
    }
    (depth, has_open)
}

fn raw_string_start(line: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut index = start;
    if line.get(index) == Some(&b'b') {
        index += 1;
    }
    if line.get(index) != Some(&b'r') {
        return None;
    }
    index += 1;
    let hash_start = index;
    while line.get(index) == Some(&b'#') {
        index += 1;
    }
    (line.get(index) == Some(&b'"')).then_some((index - hash_start, index + 1))
}

fn raw_string_ends_at(line: &[u8], start: usize, hashes: usize) -> bool {
    line.get(start) == Some(&b'"')
        && line
            .get(start + 1..start + hashes + 1)
            .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
}

fn character_literal_end(line: &[u8], start: usize) -> Option<usize> {
    let mut index = start + 1;
    if line.get(index) == Some(&b'\\') {
        index += 2;
    } else {
        index += 1;
    }
    (line.get(index) == Some(&b'\'')).then_some(index)
}

fn identifier_occurrences<'a>(
    line: &'a str,
    identifier: &'a str,
) -> impl Iterator<Item = usize> + 'a {
    line.match_indices(identifier).filter_map(|(start, _)| {
        let before = line[..start].chars().next_back();
        let after = line[start + identifier.len()..].chars().next();
        (!before.is_some_and(is_identifier_char) && !after.is_some_and(is_identifier_char))
            .then_some(start)
    })
}

fn is_identifier_char(character: char) -> bool {
    character == '_' || character.is_ascii_alphanumeric()
}

fn enclosing_test_name<'a>(
    lines: &'a [&str],
    start: usize,
    reference_line: usize,
) -> Option<&'a str> {
    lines[start..=reference_line].iter().rev().find_map(|line| {
        let rest = line.trim_start().strip_prefix("fn ")?;
        rest.split('(').next()
    })
}
