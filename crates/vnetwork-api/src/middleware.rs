use crate::errors::ApiError;
use crate::state::ApiAppState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use std::net::{IpAddr, Ipv4Addr};

pub async fn rate_limit_middleware(
    State(app): State<ApiAppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
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
