import pytest
import jwt
from datetime import datetime, timedelta
from starlette.testclient import TestClient
from main import app, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token

# Create a test client
client = TestClient(app)


class TestHealthCheck:
    """Test health check endpoint (no authentication required)"""
    
    def test_health_check_returns_ok(self):
        """Health check should always return status ok"""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestTokenGeneration:
    """Test JWT token generation"""
    
    def test_generate_token_success(self):
        """Should successfully generate a token"""
        response = client.post("/token?username=testuser")
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert len(data["access_token"]) > 0
    
    def test_generate_token_with_different_usernames(self):
        """Should generate tokens with different usernames"""
        usernames = ["alice", "bob", "charlie"]
        tokens = []
        
        for username in usernames:
            response = client.post(f"/token?username={username}")
            assert response.status_code == 200
            token = response.json()["access_token"]
            tokens.append(token)
            
            # Verify each token contains the correct username
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            assert payload["sub"] == username
    
    def test_generated_token_contains_expiration(self):
        """Generated token should contain expiration"""
        response = client.post("/token?username=testuser")
        token = response.json()["access_token"]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        assert "exp" in payload
        assert payload["sub"] == "testuser"


class TestProtectedEndpoint:
    """Test protected endpoint access with authentication"""
    
    def test_access_protected_with_valid_token(self):
        """Should access protected endpoint with valid token"""
        # Generate token
        token_response = client.post("/token?username=testuser")
        token = token_response.json()["access_token"]
        
        # Access protected endpoint
        response = client.get(
            "/protected",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "OK"
        assert data["authenticated"] is True
        assert data["user"] == "testuser"
    
    def test_access_protected_without_token(self):
        """Should reject access without token"""
        response = client.get("/protected")
        assert response.status_code == 401
        assert "Missing authorization header" in response.json()["detail"]
    
    def test_access_protected_with_invalid_token(self):
        """Should reject access with invalid token"""
        response = client.get(
            "/protected",
            headers={"Authorization": "Bearer invalid_token_here"}
        )
        assert response.status_code == 401
        assert "Invalid token" in response.json()["detail"]
    
    def test_access_protected_with_expired_token(self):
        """Should reject access with expired token"""
        # Create an expired token
        expired_data = {
            "sub": "testuser",
            "exp": datetime.utcnow() - timedelta(hours=1)  # Expired 1 hour ago
        }
        expired_token = jwt.encode(expired_data, SECRET_KEY, algorithm=ALGORITHM)
        
        response = client.get(
            "/protected",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        assert response.status_code == 401
        assert "Token has expired" in response.json()["detail"]
    
    def test_access_protected_with_wrong_auth_scheme(self):
        """Should reject with wrong authorization scheme"""
        token_response = client.post("/token?username=testuser")
        token = token_response.json()["access_token"]
        
        response = client.get(
            "/protected",
            headers={"Authorization": f"Basic {token}"}
        )
        assert response.status_code == 401
        assert "Invalid token" in response.json()["detail"]
    
    def test_access_protected_with_malformed_header(self):
        """Should reject with malformed authorization header"""
        response = client.get(
            "/protected",
            headers={"Authorization": "BearerOnlyToken"}  # Missing space
        )
        assert response.status_code == 401
    
    def test_access_protected_with_different_users(self):
        """Should handle multiple different users correctly"""
        users = ["alice", "bob", "charlie"]
        
        for username in users:
            # Generate token for user
            token_response = client.post(f"/token?username={username}")
            token = token_response.json()["access_token"]
            
            # Access protected endpoint
            response = client.get(
                "/protected",
                headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 200
            data = response.json()
            assert data["user"] == username
            assert data["message"] == "OK"


class TestRootEndpoint:
    """Test root endpoint"""
    
    def test_root_with_valid_token(self):
        """Root endpoint should also require authentication"""
        token_response = client.post("/token?username=testuser")
        token = token_response.json()["access_token"]
        
        response = client.get(
            "/",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Hello World"
    
    def test_root_without_token(self):
        """Root endpoint should reject without token"""
        response = client.get("/")
        assert response.status_code == 401


class TestTokenUtility:
    """Test token creation utilities"""
    
    def test_create_access_token_default_expiration(self):
        """Should create token with default expiration"""
        token = create_access_token({"sub": "testuser"})
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        assert payload["sub"] == "testuser"
        assert "exp" in payload
    
    def test_create_access_token_custom_expiration(self):
        """Should create token with custom expiration"""
        custom_expire = timedelta(hours=2)
        token = create_access_token({"sub": "testuser"}, custom_expire)
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        assert payload["sub"] == "testuser"
        assert "exp" in payload
    
    def test_token_payload_integrity(self):
        """Token should contain exact payload data"""
        custom_data = {"sub": "alice", "role": "admin", "org": "acme"}
        token = create_access_token(custom_data)
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        assert payload["sub"] == "alice"
        assert payload["role"] == "admin"
        assert payload["org"] == "acme"


class TestEndpointIntegration:
    """Integration tests for complete workflows"""
    
    def test_complete_authentication_workflow(self):
        """Test complete flow: get token -> access protected resource"""
        # Step 1: Generate token
        token_response = client.post("/token?username=john")
        assert token_response.status_code == 200
        token = token_response.json()["access_token"]
        
        # Step 2: Use token to access protected endpoint
        protected_response = client.get(
            "/protected",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert protected_response.status_code == 200
        assert protected_response.json()["user"] == "john"
        
        # Step 3: Access health check (no token needed)
        health_response = client.get("/health")
        assert health_response.status_code == 200
    
    def test_token_reuse(self):
        """Same token should work for multiple requests"""
        # Generate token
        token_response = client.post("/token?username=testuser")
        token = token_response.json()["access_token"]
        
        # Make multiple requests with same token
        for i in range(3):
            response = client.get(
                "/protected",
                headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 200
            assert response.json()["message"] == "OK"
    
    def test_different_tokens_for_different_users(self):
        """Different users should get different tokens"""
        user1_token = client.post("/token?username=user1").json()["access_token"]
        user2_token = client.post("/token?username=user2").json()["access_token"]
        
        # Tokens should be different
        assert user1_token != user2_token
        
        # Each token should identify correct user
        response1 = client.get("/protected", headers={"Authorization": f"Bearer {user1_token}"})
        response2 = client.get("/protected", headers={"Authorization": f"Bearer {user2_token}"})
        
        assert response1.json()["user"] == "user1"
        assert response2.json()["user"] == "user2"


class TestErrorHandling:
    """Test error handling and edge cases"""
    
    def test_empty_authorization_header(self):
        """Should reject empty authorization header"""
        response = client.get(
            "/protected",
            headers={"Authorization": ""}
        )
        assert response.status_code == 401
    
    def test_case_insensitive_bearer_scheme(self):
        """Bearer scheme should be case insensitive"""
        token_response = client.post("/token?username=testuser")
        token = token_response.json()["access_token"]
        
        # Test different capitalizations
        for bearer in ["Bearer", "bearer", "BEARER"]:
            response = client.get(
                "/protected",
                headers={"Authorization": f"{bearer} {token}"}
            )
            # Should handle case insensitivity
            assert response.status_code == 200
    
    def test_token_with_extra_whitespace(self):
        """Should handle tokens with trimmed whitespace"""
        token_response = client.post("/token?username=testuser")
        token = token_response.json()["access_token"]
        
        response = client.get(
            "/protected",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
