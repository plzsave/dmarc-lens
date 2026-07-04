//! Integration tests running the compiled `dmarc-lens` binary against
//! directories assembled with tempfile.

use std::path::Path;
use std::process::Output;

use tempfile::TempDir;

const GOOGLE: &[u8] = include_bytes!("../../dmarc-parser/tests/fixtures/google.xml");
const MICROSOFT: &[u8] = include_bytes!("../../dmarc-parser/tests/fixtures/microsoft.xml");

fn run(args: &[&str], paths: &[&Path]) -> Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_dmarc-lens"));
    cmd.arg("summary");
    for path in paths {
        cmd.arg(path);
    }
    cmd.args(args);
    cmd.output().expect("failed to run dmarc-lens")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Directory with both fixtures, one of them nested to test recursion.
fn fixture_dir() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("google.xml"), GOOGLE).unwrap();
    let nested = dir.path().join("nested");
    std::fs::create_dir(&nested).unwrap();
    std::fs::write(nested.join("microsoft.xml"), MICROSOFT).unwrap();
    dir
}

#[test]
fn human_summary_covers_all_sections() {
    let dir = fixture_dir();
    let output = run(&[], &[dir.path()]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("== Overview =="));
    assert!(text.contains("Reports analyzed  : 2 (0 file(s) failed to parse)"));
    // google 2026-06-24 .. microsoft 2026-06-25
    assert!(text.contains("Period (UTC)      : 2026-06-24 .. 2026-06-25"));
    // 48 (google) + 9 (microsoft) messages
    assert!(text.contains("Total messages    : 57"));
    assert!(text.contains("== Authentication (policy_evaluated) =="));
    assert!(text.contains("== Top sources"));
    assert!(text.contains("203.0.113.10"));
    assert!(text.contains("== Attention: sources failing both DKIM and SPF =="));
    // 192.0.2.200 fails both in google (3) and microsoft (2)
    assert!(text.contains("192.0.2.200"));
    assert!(text.contains("== Reporters =="));
    assert!(text.contains("google.com"));
    assert!(text.contains("Outlook.com"));
}

#[test]
fn json_summary_has_stable_shape() {
    let dir = fixture_dir();
    let output = run(&["--format", "json"], &[dir.path()]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();

    assert_eq!(json["reports"]["analyzed"], 2);
    assert_eq!(json["reports"]["failed_files"], 0);
    assert_eq!(json["date_range"]["begin"], 1782259200);
    assert_eq!(json["date_range"]["end_date"], "2026-06-25");
    assert_eq!(json["messages"]["total"], 57);
    // aligned pass: 40 both + 5 spf-only + 7 dkim-only = 52
    assert_eq!(json["messages"]["dmarc_pass"], 52);
    assert_eq!(json["auth"]["both_pass"], 40);
    assert_eq!(json["auth"]["dkim_only"], 7);
    assert_eq!(json["auth"]["spf_only"], 5);
    assert_eq!(json["auth"]["both_fail"], 5);

    let top = json["top_sources"].as_array().unwrap();
    assert_eq!(top[0]["ip"], "203.0.113.10");
    assert_eq!(top[0]["messages"], 40);
    assert_eq!(top[0]["dispositions"]["none"], 40);

    let failing = json["failing_sources"].as_array().unwrap();
    assert_eq!(failing.len(), 1);
    assert_eq!(failing[0]["ip"], "192.0.2.200");
    assert_eq!(failing[0]["messages"], 5);
    assert_eq!(failing[0]["first_seen"], "2026-06-24");
    assert_eq!(failing[0]["last_seen"], "2026-06-25");

    let reporters = json["reporters"].as_array().unwrap();
    assert_eq!(reporters.len(), 2);
}

#[test]
fn broken_file_warns_but_does_not_fail() {
    let dir = fixture_dir();
    std::fs::write(dir.path().join("broken.xml"), b"<feedback><oops>").unwrap();

    let output = run(&[], &[dir.path()]);
    assert!(output.status.success());
    assert!(stderr(&output).contains("broken.xml"));
    assert!(stdout(&output).contains("Reports analyzed  : 2 (1 file(s) failed to parse)"));
}

#[test]
fn no_valid_reports_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    let output = run(&[], &[dir.path()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("no valid reports"));
}

#[test]
fn domain_filter() {
    let dir = fixture_dir();

    // Case-insensitive match keeps both reports (microsoft publishes Example.com).
    let output = run(
        &["--format", "json", "--domain", "EXAMPLE.COM"],
        &[dir.path()],
    );
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(json["reports"]["analyzed"], 2);

    // Non-matching domain filters everything out -> exit 1.
    let output = run(&["--domain", "other.example"], &[dir.path()]);
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn date_filters_select_reports_by_range_overlap() {
    let dir = fixture_dir();

    // google covers 06-24, microsoft covers 06-25.
    let output = run(
        &["--format", "json", "--until", "2026-06-24"],
        &[dir.path()],
    );
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(json["reports"]["analyzed"], 1);
    assert_eq!(json["reporters"][0]["org_name"], "google.com");

    let output = run(
        &["--format", "json", "--since", "2026-06-25"],
        &[dir.path()],
    );
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(json["reports"]["analyzed"], 1);
    assert_eq!(json["reporters"][0]["org_name"], "Outlook.com");
}

#[test]
fn top_limits_source_rows() {
    let dir = fixture_dir();
    let output = run(&["--format", "json", "--top", "1"], &[dir.path()]);
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(json["top_sources"].as_array().unwrap().len(), 1);
    // The failing-sources list is not truncated by --top.
    assert_eq!(json["failing_sources"].as_array().unwrap().len(), 1);
}

#[test]
fn accepts_multiple_explicit_files() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.xml");
    let b = dir.path().join("b.xml");
    std::fs::write(&a, GOOGLE).unwrap();
    std::fs::write(&b, MICROSOFT).unwrap();

    let output = run(&["--format", "json"], &[a.as_path(), b.as_path()]);
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(json["reports"]["analyzed"], 2);
}

#[test]
fn record_warnings_go_to_stderr() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("dirty.xml"),
        include_bytes!("../../dmarc-parser/tests/fixtures/dirty.xml"),
    )
    .unwrap();

    let output = run(&[], &[dir.path()]);
    assert!(output.status.success());
    let err = stderr(&output);
    assert!(err.contains("row.source_ip"));
    assert!(err.contains("row.count"));
    assert!(stdout(&output).contains("Skipped records   : 3"));
}

#[test]
fn invalid_date_argument_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let output = run(&["--since", "not-a-date"], &[dir.path()]);
    assert_eq!(output.status.code(), Some(2));
}
