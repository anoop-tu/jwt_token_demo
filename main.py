# Import required libraries for API, authentication, and JWT handling
from fastapi import FastAPI, Depends, HTTPException, status, Header
from typing import Optional
import jwt
from datetime import datetime, timedelta

# Initialize FastAPI application with a title
app = FastAPI(title="JWT Auth API")

# ============ JWT Configuration ============
# Secret key for encoding/decoding JWT tokens (MUST be changed in production!)
SECRET_KEY = "your-secret-key-change-in-production"
# Algorithm used for JWT token encoding
ALGORITHM = "HS256"
# Token expiration time in minutes
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT access token."""
    # Make a copy of the data to avoid modifying the original
    to_encode = data.copy()
    
    # Set token expiration time
    if expires_delta:
        # Use custom expiration if provided
        expire = datetime.utcnow() + expires_delta
    else:
        # Use default expiration time
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Add expiration claim to the payload
    to_encode.update({"exp": expire})
    
    # Encode the payload into a JWT token using the secret key
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(authorization: Optional[str] = Header(None)):
    """Verify JWT token from Authorization header."""
    # Check if Authorization header is present
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header"
        )
    
    try:
        # Split authorization header into scheme and token (e.g., "Bearer <token>")
        scheme, token = authorization.split()
        
        # Verify the authorization scheme is "Bearer"
        if scheme.lower() != "bearer":
            raise ValueError("Invalid auth scheme")
        
        # Decode and verify the JWT token using the secret key
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
        
    except jwt.ExpiredSignatureError:
        # Token has expired
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except (jwt.InvalidTokenError, ValueError):
        # Token is invalid or malformed
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


# ============ API Endpoints ============

@app.post("/token")
def login(username: str = "testuser"):
    """Generate a JWT token."""
    # Create a JWT token with the username as the subject claim
    access_token = create_access_token(data={"sub": username})
    # Return the token and token type to the client
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/")
def read_root(payload: dict = Depends(verify_token)):
    """Public endpoint that returns root message."""
    # This endpoint is protected - the verify_token dependency ensures authentication
    return {"message": "Hello World"}


@app.get("/protected")
def protected_route(payload: dict = Depends(verify_token)):
    """Protected endpoint - requires valid JWT token."""
    # Access the verified token payload to get user information
    # The verify_token dependency automatically validates the token
    return {
        "message": "OK",
        "user": payload.get("sub"),  # Extract username from token payload
        "authenticated": True
    }


@app.get("/health")
def health_check():
    """Health check endpoint - no authentication required."""
    # This is a public endpoint used for monitoring and health checks
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    # Start the FastAPI server with Uvicorn ASGI server
    # host: 127.0.0.1 makes it accessible only locally
    # port: 8000 is the default FastAPI development port
    uvicorn.run(app, host="127.0.0.1", port=8000)
