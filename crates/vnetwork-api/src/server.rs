use crate::middleware::rate_limit_middleware;
use crate::rate_limits::RateLimiter;
use crate::routes;
use crate::state::{ApiAppState, NetworkNodeBackend};
use crate::websocket::ws_events_handler;
use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

#[derive(Debug, Clone)]
pub struct ApiServerConfig {
    pub bind_addr: String,
    pub max_body_bytes: usize,
    pub rate_limit_per_min: usize,
    pub tls_enabled: bool,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
}

impl Default for ApiServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8080".to_string(),
            max_body_bytes: 2 * 1024 * 1024,
            rate_limit_per_min: 1200,
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

pub fn build_router(
    backend: Arc<dyn NetworkNodeBackend>,
    rate_limit_per_min: usize,
    max_body_bytes: usize,
) -> Router {
    let app_state = ApiAppState {
        backend,
        rate_limiter: Arc::new(RateLimiter::new(rate_limit_per_min, 60)),
    };

    Router::new()
        .route("/health", get(routes::network::healthz))
        .route("/healthz", get(routes::network::healthz))
        .route("/readyz", get(routes::network::readyz))
        .route("/metrics", get(routes::network::metrics))
        .route("/v1/network/info", get(routes::network::network_info))
        .route("/v1/network/status", get(routes::network::network_status))
        .route("/v1/nodes", get(routes::nodes::list_nodes))
        .route("/v1/nodes/:node_id", get(routes::nodes::get_node))
        .route("/v1/nodes/:node_id/status", get(routes::nodes::node_status))
        .route("/v1/nodes/connect", post(routes::nodes::connect_node))
        .route(
            "/v1/participants/challenge",
            post(routes::participants::challenge),
        )
        .route("/v1/participants/join", post(routes::participants::join))
        .route(
            "/v1/participants/scope",
            post(routes::participants::manage_scope),
        )
        .route(
            "/v1/participants/:participant_id",
            get(routes::participants::get_participant),
        )
        .route(
            "/v1/participants/:participant_id/scope",
            get(routes::participants::get_participant_scope),
        )
        .route("/v1/language/parse", post(routes::language::parse_source))
        .route(
            "/v1/language/compile",
            post(routes::language::compile_source),
        )
        .route(
            "/v1/language/validate",
            post(routes::language::validate_source),
        )
        .route(
            "/v1/programs/submit",
            post(routes::programs::submit_program),
        )
        .route(
            "/v1/programs/:program_id",
            get(routes::programs::get_program),
        )
        .route(
            "/v1/programs/:program_id/status",
            get(routes::programs::get_program_status),
        )
        .route("/v1/spaces", get(routes::spaces::list_spaces))
        .route("/v1/spaces/:space_id", get(routes::spaces::get_space))
        .route("/v1/regions", get(routes::regions::list_regions))
        .route("/v1/regions/:region_id", get(routes::regions::get_region))
        .route("/v1/wallets", get(routes::wallets::list_wallets))
        .route("/v1/wallets/keys", post(routes::wallets::manage_wallet_key))
        .route(
            "/v1/wallets/policy",
            post(routes::wallets::update_wallet_receive_policy),
        )
        .route("/v1/wallets/:wallet_id", get(routes::wallets::get_wallet))
        .route("/v1/tokens", get(routes::tokens::list_tokens))
        .route("/v1/tokens/:token_id", get(routes::tokens::get_token))
        .route(
            "/v1/tokens/:token_id/supply",
            get(routes::tokens::token_supply),
        )
        .route(
            "/v1/transactions",
            post(routes::transactions::submit_transaction),
        )
        .route(
            "/v1/transactions/:transaction_id",
            get(routes::transactions::get_transaction),
        )
        .route(
            "/v1/contracts",
            get(routes::contracts::list_contracts)
                .post(routes::contracts::create_or_execute_contract),
        )
        .route(
            "/v1/contracts/:contract_id",
            get(routes::contracts::get_contract),
        )
        .route(
            "/v1/loans",
            get(routes::loans::list_loans).post(routes::loans::create_or_execute_loan),
        )
        .route("/v1/loans/:loan_id", get(routes::loans::get_loan))
        .route("/v1/ledger/events", get(routes::ledgers::list_events))
        .route("/v1/ledger/proofs", get(routes::ledgers::ledger_proofs))
        .route(
            "/v1/ledger/replay",
            get(routes::ledgers::verify_replay).post(routes::ledgers::verify_replay),
        )
        .route(
            "/v1/consensus/status",
            get(routes::consensus::consensus_status),
        )
        .route(
            "/v1/consensus/certificates",
            get(routes::consensus::list_certificates),
        )
        .route(
            "/v1/consensus/equivocations",
            get(routes::consensus::list_equivocations),
        )
        .route(
            "/v1/reconstruction/verify",
            post(routes::reconstruction::verify_reconstruction),
        )
        .route(
            "/v1/explorer/network",
            get(routes::explorer::explorer_network),
        )
        .route("/v1/ws", get(ws_events_handler))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(build_cors_layer())
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            rate_limit_middleware,
        ))
        .with_state(app_state)
}

pub fn parse_cors_allowed_origins(raw: Option<&str>) -> Vec<HeaderValue> {
    const DEFAULT_ORIGINS: [&str; 2] = ["http://127.0.0.1:3000", "http://localhost:3000"];
    let Some(val) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return DEFAULT_ORIGINS
            .iter()
            .filter_map(|origin| HeaderValue::from_str(origin).ok())
            .collect();
    };
    val.split(',')
        .map(str::trim)
        .filter(|origin| {
            !origin.is_empty()
                && *origin != "*"
                && (origin.starts_with("http://") || origin.starts_with("https://"))
        })
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect()
}

pub fn build_cors_layer() -> CorsLayer {
    let env_val = std::env::var("NETWORK_CORS_ALLOWED_ORIGINS").ok();
    let origins = parse_cors_allowed_origins(env_val.as_deref());
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            HeaderName::from_static("x-admin-token"),
        ])
}

pub async fn serve_api(
    backend: Arc<dyn NetworkNodeBackend>,
    cfg: ApiServerConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let router = build_router(backend, cfg.rate_limit_per_min, cfg.max_body_bytes);
    let addr: SocketAddr = cfg.bind_addr.parse()?;
    tracing::info!(%addr, tls = cfg.tls_enabled, "Vector Network API listening");

    if cfg.tls_enabled {
        let cert = cfg
            .tls_cert_path
            .as_ref()
            .ok_or("tls_enabled=true requires tls_cert_path")?;
        let key = cfg
            .tls_key_path
            .as_ref()
            .ok_or("tls_enabled=true requires tls_key_path")?;
        let tls_cfg = RustlsConfig::from_pem_file(cert, key).await?;
        axum_server::bind_rustls(addr, tls_cfg)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cors_allowed_origins_strict_allowlist() {
        let defaults = parse_cors_allowed_origins(None);
        assert_eq!(defaults.len(), 2);
        assert!(defaults
            .iter()
            .any(|v| v.to_str().ok() == Some("http://127.0.0.1:3000")));
        assert!(defaults
            .iter()
            .any(|v| v.to_str().ok() == Some("http://localhost:3000")));

        // Wildcard must never be accepted into the allowlist
        let wildcard = parse_cors_allowed_origins(Some("*"));
        assert!(wildcard.is_empty());

        let mixed = parse_cors_allowed_origins(Some(
            "*, https://explorer.vectornetwork.example , javascript:alert(1), http://localhost:3000",
        ));
        assert_eq!(mixed.len(), 2);
        assert_eq!(
            mixed[0].to_str().ok(),
            Some("https://explorer.vectornetwork.example")
        );
        assert_eq!(mixed[1].to_str().ok(), Some("http://localhost:3000"));
    }
}
