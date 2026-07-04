//! Turns CLI path arguments into a flat list of report files.

use std::path::{Path, PathBuf};

fn is_report_file(path: &Path) -> bool {
    let Some(name) = path.file_name() else {
        return false;
    };
    let lower = name.to_string_lossy().to_ascii_lowercase();
    lower.ends_with(".xml") || lower.ends_with(".gz") || lower.ends_with(".zip")
}

/// Expands files and directories (recursively) into report file paths.
/// Explicitly named files are kept even with an unrecognized extension so
/// the parser can report why they are unsupported. Problems are returned as
/// warnings instead of aborting the walk.
pub fn collect_files(paths: &[PathBuf]) -> (Vec<PathBuf>, Vec<String>) {
    let mut files = Vec::new();
    let mut warnings = Vec::new();
    for path in paths {
        if path.is_dir() {
            walk_dir(path, &mut files, &mut warnings);
        } else if path.exists() {
            files.push(path.clone());
        } else {
            warnings.push(format!("path not found: {}", path.display()));
        }
    }
    files.sort();
    files.dedup();
    (files, warnings)
}

fn walk_dir(dir: &Path, files: &mut Vec<PathBuf>, warnings: &mut Vec<String>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            warnings.push(format!("cannot read directory {}: {err}", dir.display()));
            return;
        }
    };
    for entry in entries {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(err) => {
                warnings.push(format!("cannot read entry in {}: {err}", dir.display()));
                continue;
            }
        };
        if path.is_dir() {
            walk_dir(&path, files, warnings);
        } else if is_report_file(&path) {
            files.push(path);
        }
    }
}
