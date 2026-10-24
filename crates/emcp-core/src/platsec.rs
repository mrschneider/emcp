#![allow(dead_code)]
//! Symbian PlatSec capability bitmask verification gate for EMCP.

#[derive(Debug, Clone, Copy)]
pub struct PlatSecGate {
    pub allowed_mask: u64,
    pub strict_mode: bool,
}

impl PlatSecGate {
    pub fn new(allowed_mask: u64, strict_mode: bool) -> Self {
        Self {
            allowed_mask,
            strict_mode,
        }
    }

    /// Verifies if granted capabilities satisfy the required capabilities.
    /// Invariant: (granted & required) == required.
    pub fn verify(&self, granted_mask: u64, required_mask: u64) -> bool {
        if required_mask == 0 {
            return true;
        }

        // Caller cannot claim capabilities beyond what its manifest allows
        let effective_granted = granted_mask & self.allowed_mask;

        (effective_granted & required_mask) == required_mask
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::capability::*;

    #[test]
    fn test_platsec_gate() {
        let gate = PlatSecGate::new(CAP_READ_FS | CAP_NET_HTTP, true);

        // Required CAP_READ_FS is allowed
        assert!(gate.verify(CAP_READ_FS, CAP_READ_FS));

        // Required CAP_WRITE_FS is denied because not in allowed_mask
        assert!(!gate.verify(CAP_WRITE_FS, CAP_WRITE_FS));

        // Caller trying to claim ambient authority without manifest allowance
        assert!(!gate.verify(CAP_SYS_ADMIN, CAP_SYS_ADMIN));
    }
}
