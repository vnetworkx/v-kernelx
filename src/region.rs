use crate::error::KernelXError;
use crate::event::{OperationType, VectorEvent, VectorState};
use crate::hash::{canonical_event_hash, canonical_payload_hash};
use crate::signature::{verify_event_signature, verifying_key_from_hex};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const REGION_CREATE_OPERATION_NAME: &str = "REGION_CREATE";
pub const REGION_TYPE_TAG: &str = "region";
pub const DEFAULT_REGION_AUTH_RATIO_BPS: u64 = 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionVisibility {
    Public,
    Private,
}

impl RegionVisibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            RegionVisibility::Public => "public",
            RegionVisibility::Private => "private",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionCreateRequest {
    pub region_name: String,
    pub region_prefix: Option<String>,
    pub suggested_title: Option<String>,
    pub visibility: RegionVisibility,
    pub section: u64,
    pub trigger_event_hash: String,
    pub creation_proof: String,
    pub access_key: Option<String>,
    pub metadata: BTreeMap<String, String>,
    pub request_signature: String,
}

impl RegionCreateRequest {
    pub fn normalized_name(&self) -> String {
        self.region_name.trim().to_ascii_lowercase()
    }

    pub fn normalized_prefix(&self) -> Option<String> {
        self.region_prefix
            .as_ref()
            .map(|v| v.trim().to_ascii_uppercase())
            .filter(|v| !v.is_empty())
    }

    pub fn lookup_key(&self) -> String {
        let prefix = self.normalized_prefix().unwrap_or_default();
        format!("{}::{}", prefix, self.normalized_name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionState {
    pub region_id: String,
    pub region_root: String,
    pub region_name: String,
    pub normalized_name: String,
    pub region_prefix: Option<String>,
    pub suggested_title: Option<String>,
    pub visibility: RegionVisibility,
    pub section: u64,
    pub auth_ratio_bps: u64,
    pub creator_public_key: String,
    pub trigger_event_hash: String,
    pub creation_proof_hash: String,
    pub access_key_hash: Option<String>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub version: u64,
    pub metadata: BTreeMap<String, String>,
}

impl RegionState {
    pub fn lookup_key(&self) -> String {
        let prefix = self
            .region_prefix
            .as_ref()
            .map(|v| v.trim().to_ascii_uppercase())
            .filter(|v| !v.is_empty())
            .unwrap_or_default();
        format!(
            "{}::{}",
            prefix,
            self.normalized_name.trim().to_ascii_lowercase()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreState {
    pub regions: BTreeMap<String, RegionState>,
    pub total_auth_ratio_bps: u64,
    pub core_root: String,
    pub version: u64,
}

impl CoreState {
    pub fn new() -> Self {
        let mut core = Self {
            regions: BTreeMap::new(),
            total_auth_ratio_bps: 0,
            core_root: String::new(),
            version: 0,
        };
        core.core_root = canonical_core_root(&core);
        core
    }

    pub fn insert_region(&mut self, region: RegionState) -> Result<(), KernelXError> {
        if self.regions.contains_key(&region.region_id) {
            return Err(KernelXError::InvalidState(format!(
                "region already exists in core: {}",
                region.region_id
            )));
        }

        self.total_auth_ratio_bps = self
            .total_auth_ratio_bps
            .checked_add(region.auth_ratio_bps)
            .ok_or_else(|| KernelXError::InvalidState("core auth ratio overflow".to_string()))?;

        self.regions.insert(region.region_id.clone(), region);
        self.version = self
            .version
            .checked_add(1)
            .ok_or_else(|| KernelXError::InvalidState("core version overflow".to_string()))?;
        self.core_root = canonical_core_root(self);
        Ok(())
    }
}

impl Default for CoreState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RegionRequestSignatureDebug {
    pub lookup_key: String,
    pub actor_public_key: String,
    pub payload_len: usize,
    pub payload_hash: String,
    pub signature_len: usize,
    pub verified: bool,
    pub canonical_preview_hex: String,
}

fn hash_hex(input: &str) -> String {
    blake3::hash(input.as_bytes()).to_hex().to_string()
}

fn canonical_region_seed_bytes(
    request: &RegionCreateRequest,
    actor_public_key: &str,
) -> Result<Vec<u8>, KernelXError> {
    let mut payload = BTreeMap::new();
    payload.insert("actor_public_key".to_string(), actor_public_key.to_string());
    payload.insert("region_name".to_string(), request.region_name.clone());
    payload.insert(
        "region_prefix".to_string(),
        request.region_prefix.clone().unwrap_or_default(),
    );
    payload.insert(
        "suggested_title".to_string(),
        request.suggested_title.clone().unwrap_or_default(),
    );
    payload.insert(
        "visibility".to_string(),
        request.visibility.as_str().to_string(),
    );
    payload.insert("section".to_string(), request.section.to_string());
    payload.insert(
        "trigger_event_hash".to_string(),
        request.trigger_event_hash.clone(),
    );
    payload.insert(
        "creation_proof_hash".to_string(),
        hash_hex(&request.creation_proof),
    );
    payload.insert(
        "access_key_hash".to_string(),
        request
            .access_key
            .as_ref()
            .map(|v| hash_hex(v))
            .unwrap_or_default(),
    );
    payload.insert(
        "metadata".to_string(),
        serde_json::to_string(&request.metadata).map_err(|e| {
            KernelXError::InvalidState(format!("region metadata serialization error: {e}"))
        })?,
    );

    serde_json::to_vec(&payload)
        .map_err(|e| KernelXError::InvalidState(format!("region seed serialization error: {e}")))
}

pub fn canonical_region_request_signature_bytes(
    request: &RegionCreateRequest,
) -> Result<Vec<u8>, KernelXError> {
    let mut payload = BTreeMap::new();
    payload.insert("region_name".to_string(), request.region_name.clone());
    payload.insert(
        "region_prefix".to_string(),
        request.region_prefix.clone().unwrap_or_default(),
    );
    payload.insert(
        "suggested_title".to_string(),
        request.suggested_title.clone().unwrap_or_default(),
    );
    payload.insert(
        "visibility".to_string(),
        request.visibility.as_str().to_string(),
    );
    payload.insert("section".to_string(), request.section.to_string());
    payload.insert(
        "trigger_event_hash".to_string(),
        request.trigger_event_hash.clone(),
    );
    payload.insert("creation_proof".to_string(), request.creation_proof.clone());
    payload.insert(
        "access_key".to_string(),
        request.access_key.clone().unwrap_or_default(),
    );
    payload.insert(
        "metadata".to_string(),
        serde_json::to_string(&request.metadata).map_err(|e| {
            KernelXError::InvalidState(format!("region metadata serialization error: {e}"))
        })?,
    );

    serde_json::to_vec(&payload)
        .map_err(|e| KernelXError::InvalidState(format!("region request serialization error: {e}")))
}

pub fn validate_region_create_request(request: &RegionCreateRequest) -> Result<(), KernelXError> {
    if request.region_name.trim().is_empty() {
        return Err(KernelXError::InvalidState(
            "region_name cannot be empty".to_string(),
        ));
    }

    if request.section == 0 {
        return Err(KernelXError::InvalidState(
            "section must be greater than zero".to_string(),
        ));
    }

    if request.trigger_event_hash.trim().is_empty() {
        return Err(KernelXError::InvalidState(
            "trigger_event_hash cannot be empty".to_string(),
        ));
    }

    if request.creation_proof.trim().is_empty() {
        return Err(KernelXError::InvalidState(
            "creation_proof cannot be empty".to_string(),
        ));
    }

    if request.request_signature.trim().is_empty() {
        return Err(KernelXError::InvalidState(
            "request_signature cannot be empty".to_string(),
        ));
    }

    match request.visibility {
        RegionVisibility::Public => {
            if request.access_key.is_some() {
                return Err(KernelXError::InvalidState(
                    "public regions must not include an access_key".to_string(),
                ));
            }
        }
        RegionVisibility::Private => {
            if request
                .access_key
                .as_ref()
                .map(|v| v.trim().is_empty())
                .unwrap_or(true)
            {
                return Err(KernelXError::InvalidState(
                    "private regions require a non-empty access_key".to_string(),
                ));
            }
        }
    }

    Ok(())
}

pub fn debug_region_create_request_signature(
    actor_public_key: &str,
    request: &RegionCreateRequest,
) -> Result<RegionRequestSignatureDebug, KernelXError> {
    let vk = verifying_key_from_hex(actor_public_key)
        .map_err(|e| KernelXError::InvalidState(format!("region actor key error: {e}")))?;

    let bytes = canonical_region_request_signature_bytes(request)?;
    let payload_hash = blake3::hash(&bytes).to_hex().to_string();
    let lookup_key = request.lookup_key();

    let verified = verify_event_signature(&vk, &bytes, &request.request_signature)
        .map_err(|e| KernelXError::InvalidState(format!("region request signature error: {e}")))?;

    Ok(RegionRequestSignatureDebug {
        lookup_key,
        actor_public_key: actor_public_key.to_string(),
        payload_len: bytes.len(),
        payload_hash,
        signature_len: request.request_signature.len(),
        verified,
        canonical_preview_hex: hex::encode(&bytes[..bytes.len().min(32)]),
    })
}

pub fn verify_region_create_request_signature(
    actor_public_key: &str,
    request: &RegionCreateRequest,
) -> Result<(), KernelXError> {
    let report = debug_region_create_request_signature(actor_public_key, request)?;

    if report.verified {
        Ok(())
    } else {
        Err(KernelXError::InvalidState(
            "region request signature verification failed".to_string(),
        ))
    }
}

pub fn canonical_region_id(
    request: &RegionCreateRequest,
    actor_public_key: &str,
    sequence: u64,
) -> Result<String, KernelXError> {
    let seed = canonical_region_seed_bytes(request, actor_public_key)?;
    let digest = blake3::hash(&seed).to_hex().to_string();
    let short = &digest[..24.min(digest.len())];
    let prefix = request
        .normalized_prefix()
        .unwrap_or_else(|| "RGN".to_string());

    Ok(format!("{}::rgn_{}::{}", prefix, short, sequence))
}

pub fn canonical_core_bytes(core: &CoreState) -> Vec<u8> {
    let mut payload = BTreeMap::new();
    payload.insert("version".to_string(), core.version.to_string());
    payload.insert(
        "total_auth_ratio_bps".to_string(),
        core.total_auth_ratio_bps.to_string(),
    );
    payload.insert("region_count".to_string(), core.regions.len().to_string());

    let mut regions = BTreeMap::new();
    for (region_id, region) in &core.regions {
        regions.insert(
            region_id.clone(),
            serde_json::to_string(region).unwrap_or_default(),
        );
    }

    payload.insert(
        "regions".to_string(),
        serde_json::to_string(&regions).unwrap_or_default(),
    );

    serde_json::to_vec(&payload).unwrap_or_default()
}

pub fn canonical_core_root(core: &CoreState) -> String {
    blake3::hash(&canonical_core_bytes(core))
        .to_hex()
        .to_string()
}

pub fn region_create_operation() -> OperationType {
    OperationType::Other(REGION_CREATE_OPERATION_NAME.to_string())
}

pub fn build_region_genesis_event(
    request: &RegionCreateRequest,
    actor_public_key: &str,
    logical_clock: u64,
    timestamp: u64,
    sequence: u64,
) -> Result<VectorEvent, KernelXError> {
    validate_region_create_request(request)?;

    let creation_proof_hash = hash_hex(&request.creation_proof);
    let access_key_hash = request.access_key.as_ref().map(|v| hash_hex(v));

    let region_id = canonical_region_id(request, actor_public_key, sequence)?;

    let mut metadata = BTreeMap::new();
    metadata.insert("region_kind".to_string(), REGION_TYPE_TAG.to_string());
    metadata.insert("region_name".to_string(), request.region_name.clone());
    metadata.insert("normalized_name".to_string(), request.normalized_name());
    metadata.insert(
        "region_prefix".to_string(),
        request.normalized_prefix().unwrap_or_default(),
    );
    metadata.insert("section".to_string(), request.section.to_string());
    metadata.insert(
        "suggested_title".to_string(),
        request.suggested_title.clone().unwrap_or_default(),
    );
    metadata.insert(
        "visibility".to_string(),
        request.visibility.as_str().to_string(),
    );
    metadata.insert(
        "creator_public_key".to_string(),
        actor_public_key.to_string(),
    );
    metadata.insert(
        "trigger_event_hash".to_string(),
        request.trigger_event_hash.clone(),
    );
    metadata.insert(
        "creation_proof_hash".to_string(),
        creation_proof_hash.clone(),
    );
    metadata.insert(
        "access_key_hash".to_string(),
        access_key_hash.clone().unwrap_or_default(),
    );
    metadata.insert(
        "initial_auth_ratio_bps".to_string(),
        DEFAULT_REGION_AUTH_RATIO_BPS.to_string(),
    );
    metadata.insert("core_registry".to_string(), "core".to_string());
    metadata.insert("default_auth_ratio".to_string(), "1.0".to_string());

    for (k, v) in &request.metadata {
        metadata.insert(format!("meta:{k}"), v.clone());
    }

    let before = VectorState::zero(0, "", REGION_TYPE_TAG);
    let after = VectorState::new(Vec::new(), "", REGION_TYPE_TAG, metadata);

    let operation = region_create_operation();
    let event_id = VectorEvent::canonical_event_id(
        &region_id,
        &region_id,
        &operation,
        logical_clock,
        sequence,
    );

    let mut event = VectorEvent::new(
        event_id,
        Vec::new(),
        region_id.clone(),
        region_id,
        operation,
        before,
        after,
        1.0,
        true,
        actor_public_key.to_string(),
        logical_clock,
        timestamp,
    );

    event.signature = request.request_signature.clone();
    event.payload_hash = canonical_payload_hash(&event);
    event.event_hash = canonical_event_hash(&event);
    Ok(event)
}

pub fn is_region_create_event(event: &VectorEvent) -> bool {
    (matches!(event.operation, OperationType::OriginCreate)
        && matches!(
            event
                .vector_after
                .metadata
                .get("region_kind")
                .map(|v| v.as_str()),
            Some(REGION_TYPE_TAG)
        ))
        || matches!(
            &event.operation,
            OperationType::Other(name) if name == REGION_CREATE_OPERATION_NAME
        )
}

pub fn region_state_from_event(event: &VectorEvent) -> Result<RegionState, KernelXError> {
    if !is_region_create_event(event) {
        return Err(KernelXError::InvalidState(
            "event is not a region creation event".to_string(),
        ));
    }

    if event.event_hash.trim().is_empty() {
        return Err(KernelXError::InvalidState(
            "region event hash cannot be empty".to_string(),
        ));
    }

    let md = &event.vector_after.metadata;

    let region_name = md
        .get("region_name")
        .cloned()
        .ok_or_else(|| KernelXError::InvalidState("missing region_name".to_string()))?;

    let normalized_name = md
        .get("normalized_name")
        .cloned()
        .ok_or_else(|| KernelXError::InvalidState("missing normalized_name".to_string()))?;

    let region_prefix = match md.get("region_prefix") {
        Some(v) if !v.trim().is_empty() => Some(v.clone()),
        _ => None,
    };

    let section = md
        .get("section")
        .ok_or_else(|| KernelXError::InvalidState("missing section".to_string()))?
        .parse::<u64>()
        .map_err(|e| KernelXError::InvalidState(format!("invalid section: {e}")))?;

    let auth_ratio_bps = match md.get("initial_auth_ratio_bps") {
        Some(v) => v.parse::<u64>().map_err(|e| {
            KernelXError::InvalidState(format!("invalid initial_auth_ratio_bps: {e}"))
        })?,
        None => DEFAULT_REGION_AUTH_RATIO_BPS,
    };

    if auth_ratio_bps == 0 {
        return Err(KernelXError::InvalidState(
            "initial_auth_ratio_bps must be greater than zero".to_string(),
        ));
    }

    let suggested_title = match md.get("suggested_title") {
        Some(v) if !v.trim().is_empty() => Some(v.clone()),
        _ => None,
    };

    let visibility = match md.get("visibility").map(|v| v.as_str()) {
        Some("public") => RegionVisibility::Public,
        Some("private") => RegionVisibility::Private,
        Some(v) => {
            return Err(KernelXError::InvalidState(format!(
                "invalid region visibility: {v}"
            )))
        }
        None => return Err(KernelXError::InvalidState("missing visibility".to_string())),
    };

    let creator_public_key = md
        .get("creator_public_key")
        .cloned()
        .ok_or_else(|| KernelXError::InvalidState("missing creator_public_key".to_string()))?;

    let trigger_event_hash = md
        .get("trigger_event_hash")
        .cloned()
        .ok_or_else(|| KernelXError::InvalidState("missing trigger_event_hash".to_string()))?;

    let creation_proof_hash = md
        .get("creation_proof_hash")
        .cloned()
        .ok_or_else(|| KernelXError::InvalidState("missing creation_proof_hash".to_string()))?;

    let access_key_hash = match md.get("access_key_hash") {
        Some(v) if !v.trim().is_empty() => Some(v.clone()),
        _ => None,
    };

    let mut metadata = BTreeMap::new();
    for (k, v) in md {
        if let Some(stripped) = k.strip_prefix("meta:") {
            metadata.insert(stripped.to_string(), v.clone());
        }
    }

    Ok(RegionState {
        region_id: event.entity_id.clone(),
        region_root: event.event_hash.clone(),
        region_name,
        normalized_name,
        region_prefix,
        suggested_title,
        visibility,
        section,
        auth_ratio_bps,
        creator_public_key,
        trigger_event_hash,
        creation_proof_hash,
        access_key_hash,
        created_at_ms: event.timestamp,
        updated_at_ms: event.timestamp,
        version: 1,
        metadata,
    })
}

pub fn apply_region_event(core: &mut CoreState, event: &VectorEvent) -> Result<(), KernelXError> {
    let region = region_state_from_event(event)?;
    core.insert_region(region)?;
    Ok(())
}

pub fn core_state_from_events(events: &[VectorEvent]) -> Result<CoreState, KernelXError> {
    let mut core = CoreState::new();

    for event in events {
        if is_region_create_event(event) {
            apply_region_event(&mut core, event)?;
        }
    }

    Ok(core)
}

pub fn authorize_region_access(region: &RegionState, access_key: Option<&str>) -> bool {
    match region.visibility {
        RegionVisibility::Public => true,
        RegionVisibility::Private => {
            let Some(expected) = region.access_key_hash.as_ref() else {
                return false;
            };
            let Some(provided) = access_key else {
                return false;
            };
            hash_hex(provided) == *expected
        }
    }
}

pub fn list_regions_from_events(events: &[VectorEvent]) -> Result<Vec<RegionState>, KernelXError> {
    let mut regions = BTreeMap::<String, RegionState>::new();

    for event in events {
        if is_region_create_event(event) {
            let region = region_state_from_event(event)?;
            regions.insert(region.region_id.clone(), region);
        }
    }

    let mut out: Vec<RegionState> = regions.into_values().collect();
    out.sort_by(|a, b| {
        a.normalized_name
            .cmp(&b.normalized_name)
            .then_with(|| a.region_prefix.cmp(&b.region_prefix))
            .then_with(|| a.section.cmp(&b.section))
            .then_with(|| a.region_id.cmp(&b.region_id))
    });
    Ok(out)
}

pub fn find_region_by_lookup_key(
    events: &[VectorEvent],
    region_name: &str,
    region_prefix: Option<&str>,
) -> Result<Option<RegionState>, KernelXError> {
    let regions = list_regions_from_events(events)?;
    let normalized_name = region_name.trim().to_ascii_lowercase();
    let normalized_prefix = region_prefix
        .map(|v| v.trim().to_ascii_uppercase())
        .filter(|v| !v.is_empty());

    Ok(regions.into_iter().find(|region| {
        region.normalized_name == normalized_name
            && region
                .region_prefix
                .as_ref()
                .map(|v| v.trim().to_ascii_uppercase())
                .filter(|v| !v.is_empty())
                == normalized_prefix
    }))
}
