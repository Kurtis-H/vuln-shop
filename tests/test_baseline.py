"""Normal behavior that must work in BOTH modes - the fixes must not break features."""

import pytest

from tests.conftest import login


@pytest.fixture(params=["vuln_client", "secure_client"])
def client(request):
    return request.getfixturevalue(request.param)


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_home_page_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Vuln Shop" in resp.text


def test_search_returns_only_public_products(client):
    names = [p["name"] for p in client.get("/api/products").json()]
    assert "Mechanical Keyboard" in names
    assert not any("INTERNAL" in n for n in names)


def test_search_filters_by_name(client):
    names = [p["name"] for p in client.get("/api/products", params={"q": "hub"}).json()]
    assert names == ["USB-C Hub"]


def test_login_rejects_wrong_password(client):
    resp = client.post("/api/login", json={"username": "alice", "password": "nope"})
    assert resp.status_code == 401


def test_user_can_read_own_order(client):
    headers = login(client, "alice", "alice123")
    resp = client.get("/api/orders/1", headers=headers)
    assert resp.status_code == 200
    assert "Alice Lane" in resp.json()["shipping_address"]


def test_orders_require_login(client):
    assert client.get("/api/orders/1").status_code == 401


def test_plain_review_is_shown(client):
    headers = login(client, "alice", "alice123")
    client.post("/api/products/1/reviews", json={"body": "Great keyboard!"}, headers=headers)
    assert "Great keyboard!" in client.get("/products/1").text


def test_chatbot_answers_normal_question(client):
    resp = client.post("/api/chat", json={"message": "How long does shipping take?"})
    assert resp.status_code == 200
    assert "business days" in resp.json()["reply"]
