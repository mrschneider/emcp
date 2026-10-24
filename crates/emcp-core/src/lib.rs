//! EMCP Core library: binary wire format, PlatSec capabilities, and token budgeting.

pub mod budget;
pub mod constants;
pub mod frame;
pub mod platsec;

pub use budget::TokenBudgetLedger;
pub use constants::*;
pub use frame::{EmcpFrame, EmcpHeader, ToolConstraints};
pub use platsec::PlatSecGate;
