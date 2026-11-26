use crate::errors::ApiResult;
use crate::state::{ApiAppState, NodeConnectHttpRequest};
use axum::extract::{Path, State};
use axum::Json;

pub async fn list_nodes(State(app): State<ApiAppState>) -> Json<serde_json::Value> {
    Json(app.backend.list_peers_and_nodes().await)
}

pub async fn get_node(
    State(app): State<ApiAppState>,
    Path(node_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let val = app.backend.get_node_details(&node_id).await?;
    Ok(Json(val))
}

pub async fn node_status(
    State(app): State<ApiAppState>,
    Path(node_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let val = app.backend.get_node_details(&node_id).await?;
    Ok(Json(val))
}

pub async fn connect_node(
    State(app): State<ApiAppState>,
    Json(req): Json<NodeConnectHttpRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let res = app.backend.connect_peer(&req.multiaddr).await?;
    Ok(Json(res))
}
