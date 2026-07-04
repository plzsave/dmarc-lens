//! dmarc-lens CLI logic. `main.rs` only delegates to [`run`].

mod args;
mod collect;
mod render;
mod summary;

use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use dmarc_parser::AggregateReport;

use args::{Cli, Command, Format, SummaryArgs};
use summary::Filters;

pub fn run() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Summary(args) => match run_summary(&args) {
            Ok(code) => code,
            Err(err) => {
                eprintln!("error: {err:#}");
                ExitCode::from(2)
            }
        },
    }
}

fn run_summary(args: &SummaryArgs) -> anyhow::Result<ExitCode> {
    let (files, warnings) = collect::collect_files(&args.paths);
    for warning in &warnings {
        eprintln!("warning: {warning}");
    }

    let mut reports: Vec<AggregateReport> = Vec::new();
    let mut failed_files = 0usize;
    for file in &files {
        match dmarc_parser::read_path(file) {
            Ok(results) => {
                for result in results {
                    match result.report {
                        Ok(report) => {
                            for record_warning in &report.warnings {
                                eprintln!("warning: {}: {record_warning}", result.source.display());
                            }
                            reports.push(report);
                        }
                        Err(err) => {
                            eprintln!("warning: {}: {err}", result.source.display());
                            failed_files += 1;
                        }
                    }
                }
            }
            Err(err) => {
                eprintln!("warning: {err}");
                failed_files += 1;
            }
        }
    }

    let filters = Filters::from_args(args.since, args.until, args.domain.clone());
    reports.retain(|report| filters.matches(report));

    let summary = summary::build_summary(&reports, failed_files, args.top);
    match args.format {
        Format::Human => print!("{}", render::render_human(&summary)),
        Format::Json => {
            let json =
                serde_json::to_string_pretty(&summary).context("failed to serialize summary")?;
            println!("{json}");
        }
    }

    if reports.is_empty() {
        eprintln!("warning: no valid reports found");
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}
