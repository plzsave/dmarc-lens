//! Serde-facing structs mirroring the RUA XML schema, plus conversion into
//! the public model.
//!
//! Every field is optional here so that a report with vendor quirks still
//! deserializes; requiredness is enforced during conversion, where we can
//! skip individual records instead of failing the whole report.

use serde::Deserialize;

use crate::ParseError;
use crate::model::{
    AggregateReport, Alignment, AuthResults, DateRange, Disposition, DkimAuthResult, DmarcResult,
    Identifiers, PolicyEvaluated, PolicyPublished, Record, RecordWarning, ReportMetadata, Row,
    SpfAuthResult,
};

#[derive(Debug, Deserialize)]
pub(crate) struct RawFeedback {
    report_metadata: Option<RawReportMetadata>,
    policy_published: Option<RawPolicyPublished>,
    #[serde(default)]
    record: Vec<RawRecord>,
}

#[derive(Debug, Deserialize)]
struct RawReportMetadata {
    org_name: Option<String>,
    email: Option<String>,
    report_id: Option<String>,
    date_range: Option<RawDateRange>,
}

#[derive(Debug, Deserialize)]
struct RawDateRange {
    begin: Option<String>,
    end: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawPolicyPublished {
    domain: Option<String>,
    adkim: Option<String>,
    aspf: Option<String>,
    p: Option<String>,
    sp: Option<String>,
    pct: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawRecord {
    row: Option<RawRow>,
    identifiers: Option<RawIdentifiers>,
    auth_results: Option<RawAuthResults>,
}

#[derive(Debug, Deserialize)]
struct RawRow {
    source_ip: Option<String>,
    count: Option<String>,
    policy_evaluated: Option<RawPolicyEvaluated>,
}

#[derive(Debug, Deserialize)]
struct RawPolicyEvaluated {
    disposition: Option<String>,
    dkim: Option<String>,
    spf: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawIdentifiers {
    header_from: Option<String>,
    envelope_from: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawAuthResults {
    #[serde(default)]
    dkim: Vec<RawDkimResult>,
    #[serde(default)]
    spf: Vec<RawSpfResult>,
}

#[derive(Debug, Deserialize)]
struct RawDkimResult {
    domain: Option<String>,
    result: Option<String>,
    selector: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawSpfResult {
    domain: Option<String>,
    result: Option<String>,
}

/// Trims and rejects empty strings, so `<foo/>` and `<foo>  </foo>` count as
/// missing.
fn non_empty(value: Option<String>) -> Option<String> {
    let trimmed = value?.trim().to_owned();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn required(value: Option<String>, field: &'static str) -> Result<String, ParseError> {
    non_empty(value).ok_or(ParseError::MissingField(field))
}

impl TryFrom<RawFeedback> for AggregateReport {
    type Error = ParseError;

    fn try_from(raw: RawFeedback) -> Result<Self, Self::Error> {
        let metadata = raw
            .report_metadata
            .ok_or(ParseError::MissingField("report_metadata"))?
            .convert()?;
        let policy_published = raw
            .policy_published
            .ok_or(ParseError::MissingField("policy_published"))?
            .convert()?;

        let mut records = Vec::with_capacity(raw.record.len());
        let mut warnings = Vec::new();
        for (index, record) in raw.record.into_iter().enumerate() {
            match record.convert() {
                Ok(record) => records.push(record),
                Err((field, message)) => warnings.push(RecordWarning {
                    record_index: index,
                    field: field.to_owned(),
                    message,
                }),
            }
        }

        Ok(AggregateReport {
            metadata,
            policy_published,
            records,
            warnings,
        })
    }
}

impl RawReportMetadata {
    fn convert(self) -> Result<ReportMetadata, ParseError> {
        let range = self
            .date_range
            .ok_or(ParseError::MissingField("report_metadata.date_range"))?;
        Ok(ReportMetadata {
            org_name: required(self.org_name, "report_metadata.org_name")?,
            email: non_empty(self.email),
            report_id: required(self.report_id, "report_metadata.report_id")?,
            date_range: DateRange {
                begin: parse_epoch(range.begin, "report_metadata.date_range.begin")?,
                end: parse_epoch(range.end, "report_metadata.date_range.end")?,
            },
        })
    }
}

fn parse_epoch(value: Option<String>, field: &'static str) -> Result<i64, ParseError> {
    let text = required(value, field)?;
    text.parse()
        .map_err(|_| ParseError::InvalidValue { field, value: text })
}

impl RawPolicyPublished {
    fn convert(self) -> Result<PolicyPublished, ParseError> {
        Ok(PolicyPublished {
            domain: required(self.domain, "policy_published.domain")?,
            adkim: non_empty(self.adkim).map(|s| Alignment::parse(&s)),
            aspf: non_empty(self.aspf).map(|s| Alignment::parse(&s)),
            p: non_empty(self.p).map(|s| Disposition::parse(&s)),
            sp: non_empty(self.sp).map(|s| Disposition::parse(&s)),
            pct: non_empty(self.pct).and_then(|s| s.parse().ok()),
        })
    }
}

impl RawRecord {
    /// Converts one `<record>`; an `Err` carries the field path and a message
    /// and causes only this record to be skipped.
    fn convert(self) -> Result<Record, (&'static str, String)> {
        let row = self.row.ok_or(("row", "element missing".to_owned()))?;

        let source_ip_text = non_empty(row.source_ip)
            .ok_or(("row.source_ip", "element missing or empty".to_owned()))?;
        let source_ip = source_ip_text.parse().map_err(|_| {
            (
                "row.source_ip",
                format!("not an IP address: {source_ip_text:?}"),
            )
        })?;

        let count_text =
            non_empty(row.count).ok_or(("row.count", "element missing or empty".to_owned()))?;
        let count = count_text
            .parse()
            .map_err(|_| ("row.count", format!("not a number: {count_text:?}")))?;

        let policy_evaluated = row
            .policy_evaluated
            .map(|pe| PolicyEvaluated {
                disposition: non_empty(pe.disposition).map(|s| Disposition::parse(&s)),
                dkim: non_empty(pe.dkim).map(|s| DmarcResult::parse(&s)),
                spf: non_empty(pe.spf).map(|s| DmarcResult::parse(&s)),
            })
            .unwrap_or_default();

        let identifiers = self
            .identifiers
            .ok_or(("identifiers", "element missing".to_owned()))?;
        let header_from = non_empty(identifiers.header_from).ok_or((
            "identifiers.header_from",
            "element missing or empty".to_owned(),
        ))?;

        let auth_results = self
            .auth_results
            .map(RawAuthResults::convert)
            .unwrap_or_default();

        Ok(Record {
            row: Row {
                source_ip,
                count,
                policy_evaluated,
            },
            identifiers: Identifiers {
                header_from,
                envelope_from: non_empty(identifiers.envelope_from),
            },
            auth_results,
        })
    }
}

impl RawAuthResults {
    fn convert(self) -> AuthResults {
        AuthResults {
            // Entries without a domain or result carry no signal; drop them
            // silently rather than failing the record.
            dkim: self
                .dkim
                .into_iter()
                .filter_map(|d| {
                    Some(DkimAuthResult {
                        domain: non_empty(d.domain)?,
                        result: non_empty(d.result)?.to_ascii_lowercase(),
                        selector: non_empty(d.selector),
                    })
                })
                .collect(),
            spf: self
                .spf
                .into_iter()
                .filter_map(|s| {
                    Some(SpfAuthResult {
                        domain: non_empty(s.domain)?,
                        result: non_empty(s.result)?.to_ascii_lowercase(),
                    })
                })
                .collect(),
        }
    }
}
