use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "vnetwork-api", about = "Vector Network Public API Gateway / Node Info")]
struct Args {
    #[arg(long, env = "NETWORK_PUBLIC_API_BIND", default_value = "0.0.0.0:8080")]
    bind: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();
    let args = Args::parse();
    eprintln!(
        "Note: To run a full connected P2P + consensus + storage node with public API, launch `vnetwork-node --api-bind {}` (NETWORK_ENABLE_PUBLIC_API=true).",
        args.bind
    );
    std::process::exit(0);
}
