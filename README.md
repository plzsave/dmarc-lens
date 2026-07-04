# dmarc-lens

A fast, forgiving CLI for analyzing DMARC aggregate reports (RUA, [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489) Appendix C) — for everyone who receives RUA reports that nobody ever looks at.

Point it at a directory of report files and get a delivery-health summary: DMARC pass rate, DKIM/SPF alignment breakdown, top sending sources, and the IPs that fail both DKIM and SPF (spoofing or misconfiguration candidates).

## Supported input

- `.xml` — raw aggregate report
- `.xml.gz` (any `.gz`) — gzip-compressed report
- `.zip` — archive containing one or more XML reports

Directories are scanned recursively. Real-world reports are messy, so the parser is deliberately tolerant: unknown elements are ignored, mixed-case values are normalized, and records with missing required fields or unparseable IPs are skipped individually (with a warning on stderr) instead of failing the whole report.

## Usage

```
dmarc-lens summary <PATH>... [OPTIONS]
```

| Option | Description |
|---|---|
| `--format <human\|json>` | Output format (default: `human`) |
| `--since <YYYY-MM-DD>` | Keep reports whose date range ends on/after this UTC date |
| `--until <YYYY-MM-DD>` | Keep reports whose date range begins on/before this UTC date |
| `--domain <DOMAIN>` | Keep reports for this published policy domain |
| `--top <N>` | Number of top source IPs to show (default: 20) |

Exit codes: `0` success (even with some unparseable files), `1` no valid reports found, `2` usage error.

## Sample output

```
$ dmarc-lens summary ./rua-reports
== Overview ==
Reports analyzed  : 3 (0 file(s) failed to parse)
Period (UTC)      : 2026-06-24 .. 2026-06-25
Total messages    : 58
DMARC pass rate   : 89.7% (52 / 58)

== Authentication (policy_evaluated) ==
DKIM              : pass 47 / fail 11
SPF               : pass 45 / fail 13
Alignment         : both pass 40 | DKIM only 7 | SPF only 5 | both fail 6

== Top sources by messages ==
SOURCE IP            MESSAGES   DKIM%    SPF%  DISPOSITION               FIRST       LAST
203.0.113.10               40    100%    100%  none:40                   2026-06-24  2026-06-24
2001:db8:4860::42           7    100%      0%  none:7                    2026-06-25  2026-06-25
192.0.2.200                 5      0%      0%  quarantine:5              2026-06-24  2026-06-25
198.51.100.7                5      0%    100%  none:5                    2026-06-24  2026-06-24

== Attention: sources failing both DKIM and SPF ==
SOURCE IP       MESSAGES   DKIM%    SPF%  DISPOSITION               FIRST       LAST
192.0.2.200            5      0%      0%  quarantine:5              2026-06-24  2026-06-25

== Reporters ==
ORG             REPORTS    MESSAGES
Outlook.com           1           9
google.com            1          48
```

`--format json` emits the same data as a stable JSON document, suitable as input for further pipelines.

Notes on the numbers:

- **DMARC pass rate** counts aligned passes (DKIM aligned pass *or* SPF aligned pass, from `policy_evaluated`), not dispositions.
- **DKIM% / SPF%** are the share of a source's messages that passed the aligned check.

## Building

```
cargo build --release
./target/release/dmarc-lens summary <PATH>...
```

## Workspace layout

- `dmarc-parser` — library crate: parsing only (`parse_report` for raw bytes, `read_path` for files). Reusable outside the CLI.
- `dmarc-cli` — the `dmarc-lens` binary: aggregation, filtering, and output formatting.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
