from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _no_ambient_controller_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Operator secrets and settings in the developer's shell must never leak into tests."""
    for name in list(os.environ):
        if name.startswith("HL_"):
            monkeypatch.delenv(name, raising=False)
