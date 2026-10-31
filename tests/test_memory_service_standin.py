"""A MemoryService built without __init__ (a test stand-in) still works."""
from __future__ import annotations

from servonaut.services.memory.service import MemoryService


def test_a_stand_in_memory_service_has_no_row_supplier_by_default():
    assert MemoryService.__new__(MemoryService)._connection_rows is None
