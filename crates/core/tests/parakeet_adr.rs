//! Keeps ADR 0004's Parakeet pin and the compiled manifest identical.

use std::path::{Path, PathBuf};

use muniment_core::asr::{
    acquisition::SOURCE_REPOSITORY, PARAKEET_MODEL_MANIFEST, PARAKEET_MODEL_MANIFESTS,
};

fn parakeet_adr() -> PathBuf {
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
                Some(name) if name.starts_with("0004-") && name.ends_with(".md")
            )
        })
        .collect();
    found.sort();
    assert_eq!(
        found.len(),
        1,
        "expected exactly one docs/decisions/0004-*.md pinning Parakeet, found {found:?}"
    );
    found.remove(0)
}

fn code_span(cell: &str) -> Option<&str> {
    let inner = cell.strip_prefix('`')?.strip_suffix('`')?;
    (!inner.is_empty() && !inner.contains('`')).then_some(inner)
}

fn table_rows(markdown: &str) -> Vec<Vec<&str>> {
    markdown
        .lines()
        .filter_map(|line| {
            let inner = line.trim().strip_prefix('|')?.strip_suffix('|')?.trim();
            Some(inner.split('|').map(str::trim).collect())
        })
        .collect()
}

#[test]
fn adr_0004_pins_the_compiled_parakeet_manifest() {
    let path = parakeet_adr();
    let markdown = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()));
    let rows = table_rows(&markdown);

    assert_eq!(
        PARAKEET_MODEL_MANIFESTS,
        [&PARAKEET_MODEL_MANIFEST],
        "the Parakeet manifest list must keep one entry"
    );

    let expected_pin = [
        ("identity", PARAKEET_MODEL_MANIFEST.identity),
        ("repository", SOURCE_REPOSITORY),
        ("revision", PARAKEET_MODEL_MANIFEST.revision),
    ];
    let pinned: Vec<(&str, &str)> = rows
        .iter()
        .filter_map(|cells| {
            if cells.len() != 2 {
                return None;
            }
            Some((code_span(cells[0])?, code_span(cells[1])?))
        })
        .filter(|(field, _)| expected_pin.iter().any(|(expected, _)| field == expected))
        .collect();
    assert_eq!(
        pinned,
        expected_pin,
        "{} must pin the compiled identity, repository, and revision once and in order",
        path.display()
    );

    let artifacts: Vec<(&str, u64, &str)> = rows
        .iter()
        .filter_map(|cells| {
            if cells.len() != 3 {
                return None;
            }
            let filename = code_span(cells[0])?;
            if !PARAKEET_MODEL_MANIFEST
                .artifacts
                .iter()
                .any(|artifact| artifact.filename == filename)
            {
                return None;
            }
            let byte_size = cells[1].replace(',', "").parse().ok()?;
            Some((filename, byte_size, code_span(cells[2])?))
        })
        .collect();
    let compiled: Vec<(&str, u64, &str)> = PARAKEET_MODEL_MANIFEST
        .artifacts
        .iter()
        .map(|artifact| (artifact.filename, artifact.byte_size, artifact.sha256))
        .collect();
    assert_eq!(
        artifacts,
        compiled,
        "{} must pin every compiled Parakeet artifact once and in order",
        path.display()
    );
}
