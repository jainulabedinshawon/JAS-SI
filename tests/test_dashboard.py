from fastapi.testclient import TestClient

from jas_si_agent.api import app


def test_root_serves_developer_console():
    response = TestClient(app).get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "JAS-SI Reality-Based" in response.text
    assert "/v1/authorize" in response.text
    assert "X-API-Key" in response.text


def test_dashboard_links_openapi_and_docs():
    response = TestClient(app).get("/")
    assert 'href="/docs"' in response.text
    assert 'href="/openapi.json"' in response.text
    assert 'href="/health"' in response.text


def test_health_endpoint_remains_json():
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["status"] == "ok"
