from __future__ import annotations

import pytest


class _MemoryStore:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def set(self, key: str, value: str) -> None:
        self.values[key] = value

    def delete(self, key: str) -> None:
        self.values.pop(key, None)


@pytest.fixture(autouse=True)
def login_state_store(monkeypatch) -> _MemoryStore:
    """Keep recorded sign-in failures out of the developer's real keyring."""
    from uribo_mcp import auth

    store = _MemoryStore()
    monkeypatch.setattr(auth, "_state_store", lambda: store)
    return store
