use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

use dmarc_parser::{
    Alignment, Disposition, DmarcResult, ParseError, ReadError, parse_report, read_path,
};

const GOOGLE: &[u8] = include_bytes!("fixtures/google.xml");
const MICROSOFT: &[u8] = include_bytes!("fixtures/microsoft.xml");
const DIRTY: &[u8] = include_bytes!("fixtures/dirty.xml");

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn parses_google_style_report() {
    let report = parse_report(GOOGLE).unwrap();

    assert_eq!(report.metadata.org_name, "google.com");
    assert_eq!(
        report.metadata.email.as_deref(),
        Some("noreply-dmarc-support@google.com")
    );
    assert_eq!(report.metadata.report_id, "8267707791559466617");
    assert_eq!(report.metadata.date_range.begin, 1782259200);
    assert_eq!(report.metadata.date_range.end, 1782345599);

    let policy = &report.policy_published;
    assert_eq!(policy.domain, "example.com");
    assert_eq!(policy.adkim, Some(Alignment::Relaxed));
    assert_eq!(policy.aspf, Some(Alignment::Relaxed));
    assert_eq!(policy.p, Some(Disposition::Quarantine));
    assert_eq!(policy.sp, Some(Disposition::None));
    assert_eq!(policy.pct, Some(100));

    assert_eq!(report.records.len(), 3);
    assert!(report.warnings.is_empty());

    let first = &report.records[0];
    assert_eq!(first.row.source_ip, ip("203.0.113.10"));
    assert_eq!(first.row.count, 40);
    assert_eq!(
        first.row.policy_evaluated.disposition,
        Some(Disposition::None)
    );
    assert_eq!(first.row.policy_evaluated.dkim, Some(DmarcResult::Pass));
    assert_eq!(first.row.policy_evaluated.spf, Some(DmarcResult::Pass));
    assert_eq!(first.identifiers.header_from, "example.com");
    assert_eq!(first.auth_results.dkim.len(), 1);
    assert_eq!(
        first.auth_results.dkim[0].selector.as_deref(),
        Some("google")
    );
    assert_eq!(first.auth_results.spf[0].result, "pass");

    let spoof = &report.records[2];
    assert_eq!(
        spoof.row.policy_evaluated.disposition,
        Some(Disposition::Quarantine)
    );
    assert_eq!(spoof.auth_results.spf[0].result, "softfail");
}

#[test]
fn tolerates_microsoft_style_dialect() {
    let report = parse_report(MICROSOFT).unwrap();

    assert_eq!(report.metadata.org_name, "Outlook.com");
    // Unknown elements (<version>, <fo>, xmlns attr) are ignored.
    assert_eq!(report.records.len(), 2);
    assert!(report.warnings.is_empty());

    // Mixed-case values are normalized.
    let policy = &report.policy_published;
    assert_eq!(policy.adkim, Some(Alignment::Relaxed));
    assert_eq!(policy.aspf, Some(Alignment::Strict));
    assert_eq!(policy.p, Some(Disposition::Quarantine));
    // Empty elements count as missing.
    assert_eq!(policy.sp, None);
    assert_eq!(policy.pct, None);

    let first = &report.records[0];
    assert_eq!(first.row.source_ip, ip("2001:db8:4860::42"));
    assert_eq!(first.row.policy_evaluated.dkim, Some(DmarcResult::Pass));
    assert_eq!(first.row.policy_evaluated.spf, Some(DmarcResult::Fail));
    assert_eq!(
        first.identifiers.envelope_from.as_deref(),
        Some("bounce.example.com")
    );
    // Empty <selector></selector> becomes None; result is lowercased.
    assert_eq!(first.auth_results.dkim[0].selector, None);
    assert_eq!(first.auth_results.spf[0].result, "softfail");

    // Second record has no dkim auth_results at all.
    assert!(report.records[1].auth_results.dkim.is_empty());
}

#[test]
fn skips_bad_records_with_field_names() {
    let report = parse_report(DIRTY).unwrap();

    assert_eq!(report.records.len(), 1);
    assert_eq!(report.warnings.len(), 3);

    let fields: Vec<&str> = report.warnings.iter().map(|w| w.field.as_str()).collect();
    assert_eq!(
        fields,
        ["row.source_ip", "row.count", "identifiers.header_from"]
    );
    assert_eq!(report.warnings[0].record_index, 0);
    assert_eq!(report.warnings[2].record_index, 2);

    // The surviving record has an omitted policy_evaluated -> all None.
    let record = &report.records[0];
    assert_eq!(record.row.source_ip, ip("203.0.113.97"));
    assert_eq!(record.row.policy_evaluated.dkim, None);
    assert_eq!(record.row.policy_evaluated.spf, None);

    // Optional metadata email is absent.
    assert_eq!(report.metadata.email, None);
}

#[test]
fn rejects_broken_xml() {
    let err = parse_report(b"<feedback><report_metadata>").unwrap_err();
    assert!(matches!(err, ParseError::Xml(_)));
}

#[test]
fn rejects_missing_report_metadata() {
    let xml =
        b"<feedback><policy_published><domain>example.com</domain></policy_published></feedback>";
    let err = parse_report(xml).unwrap_err();
    assert!(matches!(err, ParseError::MissingField("report_metadata")));
}

#[test]
fn rejects_invalid_date_range() {
    let xml = br#"<feedback>
        <report_metadata>
            <org_name>x</org_name><report_id>1</report_id>
            <date_range><begin>soon</begin><end>1</end></date_range>
        </report_metadata>
        <policy_published><domain>example.com</domain></policy_published>
    </feedback>"#;
    let err = parse_report(xml).unwrap_err();
    assert!(matches!(
        err,
        ParseError::InvalidValue {
            field: "report_metadata.date_range.begin",
            ..
        }
    ));
}

fn write_gz(path: &Path, bytes: &[u8]) {
    let file = File::create(path).unwrap();
    let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap();
}

fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = File::create(path).unwrap();
    let mut writer = zip::ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, bytes) in entries {
        writer.start_file(*name, options).unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap();
}

#[test]
fn reads_plain_xml_from_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("google.xml");
    std::fs::write(&path, GOOGLE).unwrap();

    let results = read_path(&path).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].source, path);
    assert_eq!(results[0].report.as_ref().unwrap().records.len(), 3);
}

#[test]
fn reads_gzipped_xml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("google.xml.gz");
    write_gz(&path, GOOGLE);

    let results = read_path(&path).unwrap();
    assert_eq!(results.len(), 1);
    let report = results[0].report.as_ref().unwrap();
    assert_eq!(report.metadata.org_name, "google.com");
}

#[test]
fn corrupt_gzip_is_a_per_file_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.xml.gz");
    std::fs::write(&path, b"definitely not gzip").unwrap();

    let results = read_path(&path).unwrap();
    assert_eq!(results.len(), 1);
    assert!(matches!(
        results[0].report.as_ref().unwrap_err(),
        ParseError::Read(_)
    ));
}

#[test]
fn reads_zip_with_multiple_reports() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reports.zip");
    write_zip(
        &path,
        &[
            ("google.xml", GOOGLE),
            ("readme.txt", b"ignore me"),
            ("microsoft.XML", MICROSOFT),
        ],
    );

    let results = read_path(&path).unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|r| r.report.is_ok()));
    // Zip entry sources are tagged as archive:entry.
    assert!(
        results[0]
            .source
            .to_string_lossy()
            .ends_with("reports.zip:google.xml")
    );
}

#[test]
fn zip_with_one_broken_entry_keeps_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mixed.zip");
    write_zip(
        &path,
        &[
            ("broken.xml", b"<feedback>".as_slice()),
            ("google.xml", GOOGLE),
        ],
    );

    let results = read_path(&path).unwrap();
    assert_eq!(results.len(), 2);
    assert!(results[0].report.is_err());
    assert!(results[1].report.is_ok());
}

#[test]
fn empty_zip_yields_no_reports() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.zip");
    write_zip(&path, &[]);

    let results = read_path(&path).unwrap();
    assert!(results.is_empty());
}

#[test]
fn unsupported_extension_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.pdf");
    std::fs::write(&path, b"%PDF").unwrap();

    let err = read_path(&path).unwrap_err();
    assert!(matches!(err, ReadError::UnsupportedFormat(_)));
}
