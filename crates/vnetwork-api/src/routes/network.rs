use crate::state::ApiAppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

pub async fn healthz(State(app): State<ApiAppState>) -> impl IntoResponse {
    let report = app.backend.health_report().await;
    let healthy = report
        .get("healthy")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let storage_ok = report
        .get("storage_ok")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let code = if healthy && storage_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(report))
}

pub async fn readyz(State(app): State<ApiAppState>) -> impl IntoResponse {
    let (ready, body) = app.backend.ready_report().await;
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body))
}

pub async fn metrics(State(app): State<ApiAppState>) -> impl IntoResponse {
    let txt = app.backend.metrics_prometheus().await;
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        txt,
    )
}

pub async fn network_info(State(app): State<ApiAppState>) -> Json<serde_json::Value> {
    Json(app.backend.network_info().await)
}

pub async fn network_status(State(app): State<ApiAppState>) -> Json<serde_json::Value> {
    Json(app.backend.network_status().await)
}
