//! Reading reports from the filesystem: `.xml`, `.xml.gz` / `.gz`, `.zip`.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use flate2::read::MultiGzDecoder;

use crate::{AggregateReport, ParseError, parse_report};

/// Outcome of parsing one report source (a file, or one entry inside a zip).
///
/// Keeping the `Result` per source lets a broken file coexist with good ones
/// in the same batch.
#[derive(Debug)]
pub struct ReportResult {
    /// Originating file; for zip entries this is `archive.zip:entry.xml`.
    pub source: PathBuf,
    pub report: Result<AggregateReport, ParseError>,
}

/// Errors opening or recognizing a source file (parse failures are reported
/// per report via [`ReportResult`] instead).
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to open zip archive {path}: {source}")]
    Zip {
        path: PathBuf,
        #[source]
        source: zip::result::ZipError,
    },
    #[error("unsupported file type (expected .xml, .xml.gz or .zip): {0}")]
    UnsupportedFormat(PathBuf),
}

/// Reads every report contained in `path`, auto-detecting `.xml`, `.xml.gz`
/// (any `.gz`) and `.zip` by file name. A zip archive may yield multiple
/// reports; parse failures are captured per report.
pub fn read_path(path: &Path) -> Result<Vec<ReportResult>, ReadError> {
    let lower = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    if lower.ends_with(".zip") {
        read_zip(path)
    } else if lower.ends_with(".gz") {
        Ok(vec![read_gz(path)?])
    } else if lower.ends_with(".xml") {
        let bytes = read_file(path)?;
        Ok(vec![ReportResult {
            source: path.to_owned(),
            report: parse_report(&bytes),
        }])
    } else {
        Err(ReadError::UnsupportedFormat(path.to_owned()))
    }
}

fn read_file(path: &Path) -> Result<Vec<u8>, ReadError> {
    std::fs::read(path).map_err(|source| ReadError::Io {
        path: path.to_owned(),
        source,
    })
}

fn read_gz(path: &Path) -> Result<ReportResult, ReadError> {
    let file = File::open(path).map_err(|source| ReadError::Io {
        path: path.to_owned(),
        source,
    })?;
    let mut bytes = Vec::new();
    // A truncated/corrupt gzip stream only invalidates this one report.
    let report = match MultiGzDecoder::new(file).read_to_end(&mut bytes) {
        Ok(_) => parse_report(&bytes),
        Err(err) => Err(ParseError::Read(err.to_string())),
    };
    Ok(ReportResult {
        source: path.to_owned(),
        report,
    })
}

fn read_zip(path: &Path) -> Result<Vec<ReportResult>, ReadError> {
    let file = File::open(path).map_err(|source| ReadError::Io {
        path: path.to_owned(),
        source,
    })?;
    let mut archive = zip::ZipArchive::new(file).map_err(|source| ReadError::Zip {
        path: path.to_owned(),
        source,
    })?;

    let mut results = Vec::new();
    for index in 0..archive.len() {
        let source_of = |name: &str| PathBuf::from(format!("{}:{}", path.display(), name));
        let mut entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(err) => {
                results.push(ReportResult {
                    source: source_of(&format!("#{index}")),
                    report: Err(ParseError::Read(err.to_string())),
                });
                continue;
            }
        };
        if entry.is_dir() || !entry.name().to_ascii_lowercase().ends_with(".xml") {
            continue;
        }
        let source = source_of(entry.name());
        let mut bytes = Vec::new();
        let report = match entry.read_to_end(&mut bytes) {
            Ok(_) => parse_report(&bytes),
            Err(err) => Err(ParseError::Read(err.to_string())),
        };
        results.push(ReportResult { source, report });
    }
    Ok(results)
}
