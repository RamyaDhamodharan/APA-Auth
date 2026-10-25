from fastapi.testclient import TestClient

from src.api.rest.app import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["service"] == "genworx-ap-auth"


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
