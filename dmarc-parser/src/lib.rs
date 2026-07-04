//! Parser for DMARC aggregate (RUA) reports, per RFC 7489 Appendix C.
//!
//! Real-world reports are messy: unknown elements are ignored, records with
//! missing required fields or unparseable IPs are skipped individually (and
//! surfaced via [`AggregateReport::warnings`]) instead of failing the report.
//!
//! Entry points:
//! - [`parse_report`] — parse raw XML bytes (path-independent, reusable for
//!   non-filesystem sources).
//! - [`read_path`] — read `.xml`, `.xml.gz` or `.zip` from disk; a zip may
//!   contain multiple reports.

mod model;
mod raw;
mod read;

pub use model::{
    AggregateReport, Alignment, AuthResults, DateRange, Disposition, DkimAuthResult, DmarcResult,
    Identifiers, PolicyEvaluated, PolicyPublished, Record, RecordWarning, ReportMetadata, Row,
    SpfAuthResult,
};
pub use read::{ReadError, ReportResult, read_path};

/// Errors that make an entire report unusable.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid XML: {0}")]
    Xml(#[from] quick_xml::DeError),
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid value in {field}: {value:?}")]
    InvalidValue { field: &'static str, value: String },
    #[error("failed to read report data: {0}")]
    Read(String),
}

/// Parses a single aggregate report from raw XML bytes.
///
/// The XML declaration's encoding is honored via quick-xml; input without a
/// declaration is assumed to be UTF-8.
pub fn parse_report(xml: &[u8]) -> Result<AggregateReport, ParseError> {
    let raw: raw::RawFeedback = quick_xml::de::from_reader(xml)?;
    raw.try_into()
}
