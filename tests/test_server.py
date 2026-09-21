import pytest
from app.main import app
from app.database import init_db, generate_and_store_key

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_jwks_endpoint(client):
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    data = response.get_json()
    assert "keys" in data
    assert isinstance(data["keys"], list)

def test_auth_endpoint_valid_key(client):
    response = client.post('/auth')
    assert response.status_code == 200
    data = response.get_json()
    assert "token" in data

def test_auth_endpoint_expired_key(client):
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    data = response.get_json()
    assert "token" in data
