# JWT Authentication API

A simple FastAPI application that demonstrates JWT token-based authentication.

## Features

- JWT token generation
- Request authentication using JWT tokens
- Protected endpoints
- Health check endpoint

## Project Structure

```
├── main.py              # Main API application
├── requirements.txt     # Python dependencies
├── README.md           # This file
└── .gitignore          # Git ignore rules
```

## Installation

1. Create a virtual environment:
```bash
python -m venv venv
```

2. Activate the virtual environment:
```bash
# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Start the API Server

```bash
python main.py
```

The API will start at `http://127.0.0.1:8000`

### API Endpoints

#### 1. Health Check (No Auth Required)

**Using curl:**
```bash
curl http://127.0.0.1:8000/health
```

**Using PowerShell:**
```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8000/health -Method GET
```

Response:
```json
{"status": "ok"}
```

#### 2. Generate Token

**Using curl:**
```bash
curl -X POST "http://127.0.0.1:8000/token?username=testuser"
```

**Using PowerShell:**
```powershell
$response = Invoke-RestMethod -Uri "http://127.0.0.1:8000/token?username=testuser" -Method POST
$token = $response.access_token
$token
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

#### 3. Access Protected Endpoint

**Using curl:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN_HERE" http://127.0.0.1:8000/protected
```

**Using PowerShell:**
```powershell
$token = "YOUR_TOKEN_HERE"
Invoke-RestMethod -Uri http://127.0.0.1:8000/protected `
  -Headers @{"Authorization"="Bearer $token"} `
  -Method GET
```

**Complete PowerShell workflow (get token and access protected endpoint):**
```powershell
# Get token
$response = Invoke-RestMethod -Uri "http://127.0.0.1:8000/token?username=testuser" -Method POST
$token = $response.access_token

# Access protected endpoint with token
Invoke-RestMethod -Uri http://127.0.0.1:8000/protected `
  -Headers @{"Authorization"="Bearer $token"} `
  -Method GET
```

Response (if authenticated):
```json
{
  "message": "OK",
  "user": "testuser",
  "authenticated": true
}
```

Response (if not authenticated or invalid token):
```json
{"detail": "Invalid token"}
```

## Configuration

Edit `main.py` to change:
- `SECRET_KEY`: Change to a secure random string in production
- `ALGORITHM`: JWT algorithm (default: HS256)
- `ACCESS_TOKEN_EXPIRE_MINUTES`: Token expiration time (default: 30 minutes)
- `host` and `port`: Server configuration

## Documentation

Once the server is running, access the interactive API documentation:
- Swagger UI: http://127.0.0.1:8000/docs
- ReDoc: http://127.0.0.1:8000/redoc

## Security Notes

⚠️ **Important for Production:**
- Replace `SECRET_KEY` with a secure random string
- Use environment variables for secrets (use `.env` file)
- Enable HTTPS
- Implement proper error handling
- Add input validation
- Consider using RS256 (asymmetric) JWT for better security

## Running Tests

The project includes comprehensive test coverage with 22 test cases covering:

- Health check endpoint
- Token generation
- Protected endpoint access
- Authentication failures
- Token expiration
- Authorization header formats
- Integration workflows

**Run all tests:**
```bash
pytest test_main.py -v
```

**Run specific test class:**
```bash
pytest test_main.py::TestProtectedEndpoint -v
```

**Run with coverage:**
```bash
pytest test_main.py --cov=main
```

**Note for Windows PowerShell:** The above commands work in PowerShell as well. Make sure your virtual environment is activated before running tests.

```powershell
# Activate virtual environment in PowerShell
venv\Scripts\Activate.ps1

# Run tests
pytest test_main.py -v
```

## Dependencies

- **fastapi**: Web framework
- **uvicorn**: ASGI server
- **pyjwt**: JWT token handling
- **python-dotenv**: Environment variable management
- **pytest**: Testing framework
- **httpx**: HTTP client for testing
