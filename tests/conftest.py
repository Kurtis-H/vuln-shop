"""Shared fixtures. Every test gets a fresh database and an app in a chosen mode."""

import pytest
from fastapi.testclient import TestClient

from app.chatbot import FakeLLM
from app.config import SECURE, VULNERABLE, Settings
from app.main import create_app


def _make_client(tmp_path, mode: str) -> TestClient:
    settings = Settings(mode=mode, db_path=str(tmp_path / f"{mode}.db"), llm_provider="fake")
    return TestClient(create_app(settings, llm=FakeLLM()))


@pytest.fixture
def vuln_client(tmp_path):
    with _make_client(tmp_path, VULNERABLE) as client:
        yield client


@pytest.fixture
def secure_client(tmp_path):
    with _make_client(tmp_path, SECURE) as client:
        yield client


def login(client: TestClient, username: str, password: str) -> dict:
    """Log in and return an Authorization header."""
    resp = client.post("/api/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['token']}"}
