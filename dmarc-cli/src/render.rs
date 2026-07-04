//! Human-readable rendering of the summary.

use std::fmt::Write;

use crate::summary::{SourceStat, Summary};

pub fn render_human(summary: &Summary) -> String {
    let mut out = String::new();
    overview(&mut out, summary);
    auth(&mut out, summary);
    sources_table(&mut out, "Top sources by messages", &summary.top_sources);
    attention(&mut out, summary);
    reporters(&mut out, summary);
    out
}

fn overview(out: &mut String, s: &Summary) {
    let _ = writeln!(out, "== Overview ==");
    let _ = writeln!(
        out,
        "Reports analyzed  : {} ({} file(s) failed to parse)",
        s.reports.analyzed, s.reports.failed_files
    );
    if s.reports.skipped_records > 0 {
        let _ = writeln!(
            out,
            "Skipped records   : {} (missing/invalid required fields)",
            s.reports.skipped_records
        );
    }
    match &s.date_range {
        Some(p) => {
            let _ = writeln!(
                out,
                "Period (UTC)      : {} .. {}",
                p.begin_date, p.end_date
            );
        }
        None => {
            let _ = writeln!(out, "Period (UTC)      : -");
        }
    }
    let _ = writeln!(
        out,
        "Total messages    : {}",
        group_digits(s.messages.total)
    );
    let _ = writeln!(
        out,
        "DMARC pass rate   : {:.1}% ({} / {})",
        s.messages.dmarc_pass_rate * 100.0,
        group_digits(s.messages.dmarc_pass),
        group_digits(s.messages.total),
    );
    let _ = writeln!(out);
}

fn auth(out: &mut String, s: &Summary) {
    let a = &s.auth;
    let _ = writeln!(out, "== Authentication (policy_evaluated) ==");
    let _ = writeln!(
        out,
        "DKIM              : pass {} / fail {}",
        group_digits(a.dkim_pass),
        group_digits(a.dkim_fail)
    );
    let _ = writeln!(
        out,
        "SPF               : pass {} / fail {}",
        group_digits(a.spf_pass),
        group_digits(a.spf_fail)
    );
    let _ = writeln!(
        out,
        "Alignment         : both pass {} | DKIM only {} | SPF only {} | both fail {}",
        group_digits(a.both_pass),
        group_digits(a.dkim_only),
        group_digits(a.spf_only),
        group_digits(a.both_fail),
    );
    let _ = writeln!(out);
}

fn attention(out: &mut String, s: &Summary) {
    let _ = writeln!(out, "== Attention: sources failing both DKIM and SPF ==");
    if s.failing_sources.is_empty() {
        let _ = writeln!(out, "(none)");
        let _ = writeln!(out);
    } else {
        sources_table(out, "", &s.failing_sources);
    }
}

fn sources_table(out: &mut String, title: &str, sources: &[SourceStat]) {
    if !title.is_empty() {
        let _ = writeln!(out, "== {title} ==");
    }
    if sources.is_empty() {
        let _ = writeln!(out, "(none)");
        let _ = writeln!(out);
        return;
    }
    let ip_width = sources
        .iter()
        .map(|s| s.ip.to_string().len())
        .max()
        .unwrap_or(0)
        .max("SOURCE IP".len());
    let _ = writeln!(
        out,
        "{:<ip_width$}  {:>10}  {:>6}  {:>6}  {:<24}  {:<10}  {:<10}",
        "SOURCE IP", "MESSAGES", "DKIM%", "SPF%", "DISPOSITION", "FIRST", "LAST",
    );
    for src in sources {
        let dispositions = src
            .dispositions
            .iter()
            .map(|(name, count)| format!("{name}:{count}"))
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(
            out,
            "{:<ip_width$}  {:>10}  {:>6}  {:>6}  {:<24}  {:<10}  {:<10}",
            src.ip.to_string(),
            group_digits(src.messages),
            percent(src.dkim_pass, src.messages),
            percent(src.spf_pass, src.messages),
            dispositions,
            src.first_seen,
            src.last_seen,
        );
    }
    let _ = writeln!(out);
}

fn reporters(out: &mut String, s: &Summary) {
    let _ = writeln!(out, "== Reporters ==");
    if s.reporters.is_empty() {
        let _ = writeln!(out, "(none)");
        return;
    }
    let width = s
        .reporters
        .iter()
        .map(|r| r.org_name.len())
        .max()
        .unwrap_or(0)
        .max("ORG".len());
    let _ = writeln!(
        out,
        "{:<width$}  {:>8}  {:>10}",
        "ORG", "REPORTS", "MESSAGES"
    );
    for r in &s.reporters {
        let _ = writeln!(
            out,
            "{:<width$}  {:>8}  {:>10}",
            r.org_name,
            r.reports,
            group_digits(r.messages)
        );
    }
}

fn percent(part: u64, total: u64) -> String {
    if total == 0 {
        "-".to_owned()
    } else {
        format!("{:.0}%", part as f64 / total as f64 * 100.0)
    }
}

/// 1234567 -> "1,234,567"
fn group_digits(n: u64) -> String {
    let digits = n.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    grouped
}

#[cfg(test)]
mod tests {
    use super::group_digits;

    #[test]
    fn groups_thousands() {
        assert_eq!(group_digits(0), "0");
        assert_eq!(group_digits(999), "999");
        assert_eq!(group_digits(1000), "1,000");
        assert_eq!(group_digits(1234567), "1,234,567");
    }
}
