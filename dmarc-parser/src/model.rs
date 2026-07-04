//! Public data model for DMARC aggregate reports (RFC 7489 Appendix C).

use std::fmt;
use std::net::IpAddr;

use serde::Serialize;

/// A parsed DMARC aggregate report.
#[derive(Debug, Clone, Serialize)]
pub struct AggregateReport {
    pub metadata: ReportMetadata,
    pub policy_published: PolicyPublished,
    pub records: Vec<Record>,
    /// Records that were skipped because a required field was missing or invalid.
    pub warnings: Vec<RecordWarning>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportMetadata {
    pub org_name: String,
    pub email: Option<String>,
    pub report_id: String,
    pub date_range: DateRange,
}

/// Report window as epoch seconds (UTC).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DateRange {
    pub begin: i64,
    pub end: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyPublished {
    pub domain: String,
    pub adkim: Option<Alignment>,
    pub aspf: Option<Alignment>,
    pub p: Option<Disposition>,
    pub sp: Option<Disposition>,
    pub pct: Option<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub row: Row,
    pub identifiers: Identifiers,
    pub auth_results: AuthResults,
}

#[derive(Debug, Clone, Serialize)]
pub struct Row {
    pub source_ip: IpAddr,
    pub count: u64,
    pub policy_evaluated: PolicyEvaluated,
}

/// Aggregate verdicts. Fields are `None` when the reporter omitted them.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PolicyEvaluated {
    pub disposition: Option<Disposition>,
    pub dkim: Option<DmarcResult>,
    pub spf: Option<DmarcResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Identifiers {
    pub header_from: String,
    pub envelope_from: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AuthResults {
    pub dkim: Vec<DkimAuthResult>,
    pub spf: Vec<SpfAuthResult>,
}

/// Raw DKIM verification result. `result` is kept as a lowercased string
/// (`pass`, `fail`, `neutral`, `temperror`, ...) to stay tolerant of dialects.
#[derive(Debug, Clone, Serialize)]
pub struct DkimAuthResult {
    pub domain: String,
    pub result: String,
    pub selector: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpfAuthResult {
    pub domain: String,
    pub result: String,
}

/// Policy disposition (`p`, `sp`, and `policy_evaluated.disposition`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Disposition {
    None,
    Quarantine,
    Reject,
    #[serde(untagged)]
    Other(String),
}

impl Disposition {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" => Self::None,
            "quarantine" => Self::Quarantine,
            "reject" => Self::Reject,
            other => Self::Other(other.to_owned()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::None => "none",
            Self::Quarantine => "quarantine",
            Self::Reject => "reject",
            Self::Other(s) => s,
        }
    }
}

impl fmt::Display for Disposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// DMARC-aligned result from `policy_evaluated`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DmarcResult {
    Pass,
    Fail,
    #[serde(untagged)]
    Other(String),
}

impl DmarcResult {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "pass" => Self::Pass,
            "fail" => Self::Fail,
            other => Self::Other(other.to_owned()),
        }
    }

    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }
}

/// Alignment mode (`adkim` / `aspf`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Alignment {
    #[serde(rename = "r")]
    Relaxed,
    #[serde(rename = "s")]
    Strict,
    #[serde(untagged)]
    Other(String),
}

impl Alignment {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "r" | "relaxed" => Self::Relaxed,
            "s" | "strict" => Self::Strict,
            other => Self::Other(other.to_owned()),
        }
    }
}

/// A record that was skipped during conversion, with the offending field.
#[derive(Debug, Clone, Serialize)]
pub struct RecordWarning {
    /// Zero-based index of the `<record>` element in the report.
    pub record_index: usize,
    /// Dotted path of the field that was missing or invalid.
    pub field: String,
    pub message: String,
}

impl fmt::Display for RecordWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "record {} skipped: {} ({})",
            self.record_index, self.field, self.message
        )
    }
}
