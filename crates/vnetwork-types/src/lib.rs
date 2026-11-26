pub mod amount;
pub mod authorization;
pub mod canonical;
pub mod commitments;
pub mod consensus;
pub mod entity;
pub mod error;
pub mod event;
pub mod hierarchy;
pub mod identity;
pub mod ids;
pub mod operation;
pub mod protocol_version;
pub mod token;

pub use amount::*;
pub use authorization::*;
pub use canonical::*;
pub use commitments::*;
pub use consensus::*;
pub use entity::*;
pub use error::*;
pub use event::*;
pub use hierarchy::*;
pub use identity::*;
pub use ids::*;
pub use operation::*;
pub use protocol_version::*;
pub use token::*;

pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
