//! Aggregation of parsed reports into the summary model shared by the human
//! and JSON renderers. The JSON shape is the public contract for future
//! pipeline use — extend it, don't rename fields.

use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::{DateTime, NaiveDate};
use dmarc_parser::AggregateReport;
use serde::Serialize;

/// Report-level filters. Timestamps are epoch seconds (UTC).
#[derive(Debug, Default)]
pub struct Filters {
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub domain: Option<String>,
}

impl Filters {
    pub fn from_args(
        since: Option<NaiveDate>,
        until: Option<NaiveDate>,
        domain: Option<String>,
    ) -> Self {
        Self {
            since: since.map(day_start),
            // Inclusive end date: anything before the next day's start.
            until: until.map(|d| day_start(d) + 86_400),
            domain,
        }
    }

    /// A report matches when its date range overlaps the filter window and
    /// its published domain matches (case-insensitively).
    pub fn matches(&self, report: &AggregateReport) -> bool {
        let range = report.metadata.date_range;
        if self.since.is_some_and(|since| range.end < since) {
            return false;
        }
        if self.until.is_some_and(|until| range.begin >= until) {
            return false;
        }
        if let Some(domain) = &self.domain
            && !report.policy_published.domain.eq_ignore_ascii_case(domain)
        {
            return false;
        }
        true
    }
}

fn day_start(date: NaiveDate) -> i64 {
    date.and_hms_opt(0, 0, 0)
        .map(|dt| dt.and_utc().timestamp())
        .unwrap_or_default()
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub reports: ReportCounts,
    /// Overall observed window; `None` when no reports matched.
    pub date_range: Option<Period>,
    pub messages: MessageStats,
    pub auth: AuthStats,
    pub top_sources: Vec<SourceStat>,
    /// Sources where no message passed either DKIM or SPF (spoofing or
    /// misconfiguration candidates).
    pub failing_sources: Vec<SourceStat>,
    pub reporters: Vec<ReporterStat>,
}

#[derive(Debug, Serialize)]
pub struct ReportCounts {
    pub analyzed: usize,
    pub failed_files: usize,
    /// Records skipped inside otherwise-valid reports.
    pub skipped_records: usize,
}

#[derive(Debug, Serialize)]
pub struct Period {
    pub begin: i64,
    pub end: i64,
    pub begin_date: String,
    pub end_date: String,
}

#[derive(Debug, Serialize)]
pub struct MessageStats {
    pub total: u64,
    /// DMARC-aligned pass: DKIM aligned pass OR SPF aligned pass.
    pub dmarc_pass: u64,
    pub dmarc_fail: u64,
    pub dmarc_pass_rate: f64,
}

#[derive(Debug, Serialize)]
pub struct AuthStats {
    pub dkim_pass: u64,
    pub dkim_fail: u64,
    pub spf_pass: u64,
    pub spf_fail: u64,
    pub both_pass: u64,
    pub dkim_only: u64,
    pub spf_only: u64,
    pub both_fail: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceStat {
    pub ip: IpAddr,
    pub messages: u64,
    pub dkim_pass: u64,
    pub spf_pass: u64,
    /// Message counts per disposition, e.g. `{"none": 120, "reject": 3}`.
    pub dispositions: BTreeMap<String, u64>,
    pub first_seen: String,
    pub last_seen: String,
    #[serde(skip)]
    pub first_seen_ts: i64,
    #[serde(skip)]
    pub last_seen_ts: i64,
}

#[derive(Debug, Serialize)]
pub struct ReporterStat {
    pub org_name: String,
    pub reports: usize,
    pub messages: u64,
}

pub fn format_date(epoch: i64) -> String {
    DateTime::from_timestamp(epoch, 0)
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| format!("epoch:{epoch}"))
}

pub fn build_summary(reports: &[AggregateReport], failed_files: usize, top: usize) -> Summary {
    let mut total: u64 = 0;
    let mut both_pass: u64 = 0;
    let mut dkim_only: u64 = 0;
    let mut spf_only: u64 = 0;
    let mut both_fail: u64 = 0;
    let mut period: Option<(i64, i64)> = None;
    let mut sources: BTreeMap<IpAddr, SourceStat> = BTreeMap::new();
    let mut reporters: BTreeMap<String, ReporterStat> = BTreeMap::new();
    let mut skipped_records = 0;

    for report in reports {
        let range = report.metadata.date_range;
        period = match period {
            Some((begin, end)) => Some((begin.min(range.begin), end.max(range.end))),
            None => Some((range.begin, range.end)),
        };
        skipped_records += report.warnings.len();

        let reporter = reporters
            .entry(report.metadata.org_name.clone())
            .or_insert_with(|| ReporterStat {
                org_name: report.metadata.org_name.clone(),
                reports: 0,
                messages: 0,
            });
        reporter.reports += 1;

        for record in &report.records {
            let row = &record.row;
            let count = row.count;
            total += count;
            reporter.messages += count;

            let dkim_pass = row
                .policy_evaluated
                .dkim
                .as_ref()
                .is_some_and(|r| r.is_pass());
            let spf_pass = row
                .policy_evaluated
                .spf
                .as_ref()
                .is_some_and(|r| r.is_pass());
            match (dkim_pass, spf_pass) {
                (true, true) => both_pass += count,
                (true, false) => dkim_only += count,
                (false, true) => spf_only += count,
                (false, false) => both_fail += count,
            }

            let stat = sources.entry(row.source_ip).or_insert_with(|| SourceStat {
                ip: row.source_ip,
                messages: 0,
                dkim_pass: 0,
                spf_pass: 0,
                dispositions: BTreeMap::new(),
                first_seen: String::new(),
                last_seen: String::new(),
                first_seen_ts: range.begin,
                last_seen_ts: range.end,
            });
            stat.messages += count;
            if dkim_pass {
                stat.dkim_pass += count;
            }
            if spf_pass {
                stat.spf_pass += count;
            }
            let disposition = row
                .policy_evaluated
                .disposition
                .as_ref()
                .map(|d| d.to_string())
                .unwrap_or_else(|| "unknown".to_owned());
            *stat.dispositions.entry(disposition).or_insert(0) += count;
            stat.first_seen_ts = stat.first_seen_ts.min(range.begin);
            stat.last_seen_ts = stat.last_seen_ts.max(range.end);
        }
    }

    let mut sources: Vec<SourceStat> = sources.into_values().collect();
    for stat in &mut sources {
        stat.first_seen = format_date(stat.first_seen_ts);
        stat.last_seen = format_date(stat.last_seen_ts);
    }
    sources.sort_by(|a, b| b.messages.cmp(&a.messages).then(a.ip.cmp(&b.ip)));

    let failing_sources: Vec<SourceStat> = sources
        .iter()
        .filter(|s| s.dkim_pass == 0 && s.spf_pass == 0)
        .cloned()
        .collect();
    sources.truncate(top);

    let mut reporters: Vec<ReporterStat> = reporters.into_values().collect();
    reporters.sort_by(|a, b| {
        b.reports
            .cmp(&a.reports)
            .then_with(|| a.org_name.cmp(&b.org_name))
    });

    let dmarc_pass = both_pass + dkim_only + spf_only;
    Summary {
        reports: ReportCounts {
            analyzed: reports.len(),
            failed_files,
            skipped_records,
        },
        date_range: period.map(|(begin, end)| Period {
            begin,
            end,
            begin_date: format_date(begin),
            end_date: format_date(end),
        }),
        messages: MessageStats {
            total,
            dmarc_pass,
            dmarc_fail: both_fail,
            dmarc_pass_rate: if total == 0 {
                0.0
            } else {
                dmarc_pass as f64 / total as f64
            },
        },
        auth: AuthStats {
            dkim_pass: both_pass + dkim_only,
            dkim_fail: spf_only + both_fail,
            spf_pass: both_pass + spf_only,
            spf_fail: dkim_only + both_fail,
            both_pass,
            dkim_only,
            spf_only,
            both_fail,
        },
        top_sources: sources,
        failing_sources,
        reporters,
    }
}
