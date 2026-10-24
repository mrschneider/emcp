"""
Token Budget Escrow Ledger for tool execution in EMCP.
"""

from typing import Dict, Optional


class EscrowEntry:
    def __init__(self, reserved: int):
        self.reserved = reserved
        self.spent = 0
        self.committed = False


class TokenBudgetLedger:
    def __init__(self, capacity: int = 1_000_000):
        self.capacity = capacity
        self.allocated = 0
        self._escrows: Dict[int, EscrowEntry] = {}

    def escrow(self, tx_id: int, amount: int) -> bool:
        if amount == 0:
            self._escrows[tx_id] = EscrowEntry(reserved=0)
            return True

        if self.allocated + amount > self.capacity:
            return False

        self.allocated += amount
        self._escrows[tx_id] = EscrowEntry(reserved=amount)
        return True

    def spend(self, tx_id: int, amount: int) -> bool:
        entry = self._escrows.get(tx_id)
        if not entry:
            return False

        if entry.reserved > 0 and (entry.spent + amount > entry.reserved):
            return False

        entry.spent += amount
        return True

    def commit(self, tx_id: int) -> Optional[int]:
        entry = self._escrows.get(tx_id)
        if not entry:
            return None

        entry.committed = True
        unused = entry.reserved - entry.spent if entry.reserved > entry.spent else 0
        self.allocated = max(0, self.allocated - unused)
        return unused

    def refund(self, tx_id: int) -> bool:
        entry = self._escrows.pop(tx_id, None)
        if not entry:
            return False

        if not entry.committed and entry.reserved > 0:
            self.allocated = max(0, self.allocated - entry.reserved)
        return True
