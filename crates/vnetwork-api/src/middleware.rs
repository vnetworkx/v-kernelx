use crate::errors::ApiError;
use crate::state::ApiAppState;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn trust_proxy_headers() -> bool {
    std::env::var("NETWORK_TRUST_PROXY_HEADERS")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

pub async fn rate_limit_middleware(
    State(app): State<ApiAppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let socket_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    let forwarded_ip = if trust_proxy_headers() {
        req.headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
    } else {
        None
    };

    let ip = forwarded_ip
        .or(socket_ip)
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

    if !app.rate_limiter.allow(ip) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMIT_EXCEEDED",
            "rate limit exceeded",
        ));
    }
    Ok(next.run(req).await)
}
