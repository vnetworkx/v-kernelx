mod commands;
mod config;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "vn", version = "0.2.0", about = "Vector Network CLI")]
struct Cli {
    #[arg(long, global = true, env = "VNETWORK_CLI_PASSPHRASE")]
    passphrase: Option<String>,
    #[arg(long, global = true)]
    passphrase_file: Option<PathBuf>,
    #[arg(long, global = true, default_value_t = false)]
    allow_plaintext_key_fallback: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Network {
        #[command(subcommand)]
        sub: NetworkCmd,
    },
    Connect {
        #[arg(long)]
        network: Option<String>,
        #[arg(long)]
        endpoint: Option<String>,
    },
    Identity {
        #[command(subcommand)]
        sub: IdentityCmd,
    },
    Join {
        #[arg(long = "scope")]
        scopes: Vec<String>,
        #[arg(long = "auth-file")]
        auth_file: Option<PathBuf>,
    },
    Participation {
        #[command(subcommand)]
        sub: ParticipationCmd,
    },
    Node {
        #[command(subcommand)]
        sub: NodeCmd,
    },
    Language {
        #[command(subcommand)]
        sub: LanguageCmd,
    },
    Program {
        #[command(subcommand)]
        sub: ProgramCmd,
    },
    Transaction {
        #[command(subcommand)]
        sub: TransactionCmd,
    },
    Ledger {
        #[command(subcommand)]
        sub: LedgerCmd,
    },
    Query {
        path: String,
    },
    Reconstruct {
        entity_kind: String,
        entity_id: String,
    },
}

#[derive(Subcommand, Debug)]
enum NetworkCmd {
    Info,
}

#[derive(Subcommand, Debug)]
enum IdentityCmd {
    Create {
        #[arg(long)]
        name: Option<String>,
    },
    Show,
}

#[derive(Subcommand, Debug)]
enum ParticipationCmd {
    Status,
}

#[derive(Subcommand, Debug)]
enum NodeCmd {
    Status,
}

#[derive(Subcommand, Debug)]
enum LanguageCmd {
    Check { file: PathBuf },
    Compile { file: PathBuf },
}

#[derive(Subcommand, Debug)]
enum ProgramCmd {
    Submit { file: PathBuf },
}

#[derive(Subcommand, Debug)]
enum TransactionCmd {
    Status { transaction_id: String },
}

#[derive(Subcommand, Debug)]
enum LedgerCmd {
    Verify,
    Replay,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let passphrase = config::resolve_cli_passphrase(
        cli.passphrase.as_deref(),
        cli.passphrase_file.as_deref(),
    )?;
    let allow_plain = cli.allow_plaintext_key_fallback;

    match cli.command {
        Commands::Network { sub: NetworkCmd::Info } => commands::status::run_network_info().await?,
        Commands::Connect { network, endpoint } => {
            commands::connect::run_connect(network, endpoint).await?
        }
        Commands::Identity { sub } => match sub {
            IdentityCmd::Create { name } => commands::identity::run_identity_create(
                name,
                passphrase.as_deref(),
                allow_plain,
            )?,
            IdentityCmd::Show => commands::identity::run_identity_show()?,
        },
        Commands::Join { scopes, auth_file } => {
            commands::join::run_join(scopes, auth_file, passphrase.as_deref(), allow_plain).await?
        }
        Commands::Participation {
            sub: ParticipationCmd::Status,
        } => commands::status::run_participation_status().await?,
        Commands::Node {
            sub: NodeCmd::Status,
        } => commands::node::run_node_status().await?,
        Commands::Language { sub } => match sub {
            LanguageCmd::Check { file } => commands::compile::run_language_check(file)?,
            LanguageCmd::Compile { file } => commands::compile::run_language_compile(file)?,
        },
        Commands::Program {
            sub: ProgramCmd::Submit { file },
        } => {
            commands::submit::run_program_submit(file, passphrase.as_deref(), allow_plain).await?
        }
        Commands::Transaction {
            sub: TransactionCmd::Status { transaction_id },
        } => commands::transaction::run_tx_status(&transaction_id).await?,
        Commands::Ledger { sub } => match sub {
            LedgerCmd::Verify => commands::status::run_ledger_verify().await?,
            LedgerCmd::Replay => commands::status::run_ledger_replay().await?,
        },
        Commands::Query { path } => commands::query::run_query(&path).await?,
        Commands::Reconstruct {
            entity_kind,
            entity_id,
        } => commands::query::run_reconstruct(&entity_kind, &entity_id).await?,
    }
    Ok(())
}
