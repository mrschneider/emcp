#![allow(dead_code)]
//! Kernel-style Token Budget Escrow Ledger for tool execution in EMCP.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy)]
pub struct EscrowEntry {
    pub reserved: u32,
    pub spent: u32,
    pub committed: bool,
}

#[derive(Debug)]
pub struct TokenBudgetLedger {
    pub capacity: u32,
    pub allocated: u32,
    escrows: HashMap<u64, EscrowEntry>,
}

impl TokenBudgetLedger {
    pub fn new(capacity: u32) -> Self {
        Self {
            capacity,
            allocated: 0,
            escrows: HashMap::new(),
        }
    }

    /// Reserves an escrow envelope for a transaction.
    /// Returns false if capacity would be exceeded.
    pub fn escrow(&mut self, tx_id: u64, amount: u32) -> bool {
        if amount == 0 {
            // Unlimited
            self.escrows.insert(
                tx_id,
                EscrowEntry {
                    reserved: 0,
                    spent: 0,
                    committed: false,
                },
            );
            return true;
        }

        if self.allocated + amount > self.capacity {
            return false;
        }

        self.allocated += amount;
        self.escrows.insert(
            tx_id,
            EscrowEntry {
                reserved: amount,
                spent: 0,
                committed: false,
            },
        );
        true
    }

    /// Increments spend within an active escrow envelope.
    /// Returns false if transaction exceeds its envelope.
    pub fn spend(&mut self, tx_id: u64, amount: u32) -> bool {
        if let Some(entry) = self.escrows.get_mut(&tx_id) {
            if entry.reserved > 0 && (entry.spent + amount > entry.reserved) {
                return false;
            }
            entry.spent += amount;
            return true;
        }
        false
    }

    /// Commits transaction spend and releases unused reserved capacity.
    /// Returns the remaining unspent tokens.
    ///
    /// Terminal state: the escrow is dropped on commit (mirrors the Python
    /// ledger). Keeping it grew `escrows` by one entry per tool call,
    /// forever, in a long-running daemon; a post-commit `spend()` now
    /// correctly returns false instead of touching a corpse.
    pub fn commit(&mut self, tx_id: u64) -> Option<u32> {
        let entry = self.escrows.remove(&tx_id)?;
        let unused = if entry.reserved > entry.spent {
            entry.reserved - entry.spent
        } else {
            0
        };
        self.allocated = self.allocated.saturating_sub(unused);
        Some(unused)
    }

    /// Refunds the entire reservation upon tool failure.
    /// Returns false if the transaction is not in escrow.
    pub fn refund(&mut self, tx_id: u64) -> bool {
        if let Some(entry) = self.escrows.remove(&tx_id) {
            if !entry.committed && entry.reserved > 0 {
                self.allocated = self.allocated.saturating_sub(entry.reserved);
            }
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_escrow_settle_refund() {
        let mut ledger = TokenBudgetLedger::new(10_000);

        // Escrow 2000 tokens
        assert!(ledger.escrow(1, 2000));
        assert_eq!(ledger.allocated, 2000);

        // Spend 800 tokens
        assert!(ledger.spend(1, 800));

        // Spending 1500 more would exceed 2000 envelope -> rejected
        assert!(!ledger.spend(1, 1500));

        // Commit transaction -> remaining 1200 refunded to capacity
        let remaining = ledger.commit(1);
        assert_eq!(remaining, Some(1200));
        assert_eq!(ledger.allocated, 800);

        // Failure on transaction 2 -> total refund
        assert!(ledger.escrow(2, 3000));
        assert_eq!(ledger.allocated, 3800);
        assert!(ledger.refund(2));
        assert_eq!(ledger.allocated, 800);
    }

    #[test]
    fn test_escrows_dropped_on_commit_and_refund() {
        // Regression: commit used to keep the entry (and refund only
        // popped), so a long-running daemon grew escrows by one entry
        // per tool call, forever. Both terminal states must drop it.
        let mut ledger = TokenBudgetLedger::new(10_000);

        assert!(ledger.escrow(1, 2000));
        assert!(ledger.spend(1, 500));
        assert_eq!(ledger.commit(1), Some(1500));
        assert!(ledger.escrows.is_empty(), "commit must drop the escrow");
        // Post-commit spend must fail, not touch a corpse entry.
        assert!(!ledger.spend(1, 1));

        assert!(ledger.escrow(2, 3000));
        assert!(ledger.refund(2));
        assert!(ledger.escrows.is_empty(), "refund must drop the escrow");
    }
}
