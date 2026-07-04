use std::path::PathBuf;

use chrono::NaiveDate;
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "dmarc-lens",
    version,
    about = "Analyze DMARC aggregate (RUA) reports"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Summarize aggregate reports from files or directories
    Summary(SummaryArgs),
}

#[derive(Debug, clap::Args)]
pub struct SummaryArgs {
    /// Report files or directories (scanned recursively).
    /// Supported: .xml, .xml.gz, .zip
    #[arg(required = true, value_name = "PATH")]
    pub paths: Vec<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Human)]
    pub format: Format,

    /// Keep only reports whose date range ends on/after this UTC date
    #[arg(long, value_name = "YYYY-MM-DD")]
    pub since: Option<NaiveDate>,

    /// Keep only reports whose date range begins on/before this UTC date
    #[arg(long, value_name = "YYYY-MM-DD")]
    pub until: Option<NaiveDate>,

    /// Keep only reports for this published policy domain
    #[arg(long)]
    pub domain: Option<String>,

    /// Number of top source IPs to show
    #[arg(long, default_value_t = 20, value_name = "N")]
    pub top: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Human,
    Json,
}
