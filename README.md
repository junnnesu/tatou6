# tatou
A web platform for pdf watermarking. This project is intended for pedagogical use, and contain security vulnerabilities. Do not deploy on an open network.

## Features

- **Multi-Method Watermarking**: Support for multiple watermarking techniques
  - Text overlay watermarking
  - Metadata-based watermarking
  - EOF (End of File) watermarking
  - Encrypted comment watermarking
  - Zero-width character steganography
- **User Authentication**: Secure JWT-based authentication system
- **Document Management**: Upload, store, and manage PDF documents
- **Version Control**: Create and manage multiple watermarked versions
- **RMAP Protocol**: Secure group-based document access via encrypted messaging
- **Security Monitoring**: Real-time security event logging and monitoring
- **RESTful API**: Comprehensive API for all operations

## Prerequisites

- **Docker** (version 20.10+)
- **Docker Compose** (version 2.0+)
- **Python** 3.11+ 
- **Git**

## Installation

### Clone the Repository

The following instructions are meant for a bash terminal on a Linux machine. If you are using something else, you will need to adapt them.

To clone the repo, you can simply run:

```bash
git clone https://github.com/cyywww/tatou.git
```

### Environment Configuration

Create your environment configuration file:

```bash
cp sample.env .env
```

Edit `.env`:

```.env
MARIADB_ROOT_PASSWORD=your_secure_root_password
MARIADB_USER=tatou
MARIADB_PASSWORD=your_secure_db_password
FLAG_2=your_flag_value_here
FLASK_ENV=production
FLASK_DEBUG=False
DEBUG=False
```

### Deploy the Application

Build and start services:

```bash
# Build images and start all services
docker compose up --build -d

# View logs in real-time
docker compose logs -f

# View logs for specific service
docker compose logs -f server
```

Verify services:

```bash
# Check service status
docker compose ps

# Test API health
curl http://localhost:5000/healthz

# Or using httpie
http :5000/healthz
```

### Access the Application

- **Web Interface**: http://localhost:5000
- **API**: http://localhost:5000/api
- **phpMyAdmin**: http://localhost:8080

## Testing

### Unit Tests

Run python unit tests

```bash
cd tatou/server

# Create a python virtual environement
python3 -m venv .venv

# Activate your virtual environement
. .venv/bin/activate

# Install the necessary dependencies
python -m pip install -e ".[dev]"

# Run the unit tests
python -m pytest

# Run with verbose output
python -m pytest -v

# Run specific test file
python -m pytest test/test_watermarking_all_methods.py

# Run specific test
python -m pytest test/test_api.py::test_healthz_route
```

### Test Coverage Analysis

Generate and view test coverage reports:

```bash
cd server

# Run tests with coverage
python -m pytest --cov=src --cov-report=html --cov-report=term

# View coverage report in browser
# Open htmlcov/index.html in your browser

# Generate coverage report in terminal
python -m pytest --cov=src --cov-report=term-missing
```

### API Testing

#### Manual API Testing 

```bash
# Health check
curl -X GET http://localhost:5000/healthz

# Create user
curl -X POST http://localhost:5000/api/create-user \
  -H "Content-Type: application/json" \
  -d '{
    "login": "testuser",
    "email": "test@example.com",
    "password": "SecurePass123!"
  }'

# Login
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!"
  }'

# Upload document (requires auth token)
curl -X POST http://localhost:5000/api/upload-document \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -F "file=@/path/to/document.pdf" \
  -F "name=My Document"

# List documents
curl -X GET http://localhost:5000/api/list-documents \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

#### Using HTTPie

```bash
# Install httpie
pip install httpie

# Health check
http GET :5000/healthz

# Create user
http POST :5000/api/create-user \
  login=testuser \
  email=test@example.com \
  password=SecurePass123!

# Login and save token
http POST :5000/api/login \
  email=test@example.com \
  password=SecurePass123! \
  | jq -r '.token' > token.txt

# Use token for authenticated requests
http GET :5000/api/list-documents \
  "Authorization: Bearer $(cat token.txt)"
```

#### Automated API Tests

Create a test script (`test_api.sh`):

```bash
#!/bin/bash

BASE_URL="http://localhost:5000"
TOKEN=""

# Test health endpoint
echo "Testing health endpoint..."
http GET $BASE_URL/healthz

# Test user creation
echo "Creating test user..."
http POST $BASE_URL/api/create-user \
  login=apitest \
  email=apitest@example.com \
  password=TestPass123!

# Test login and get token
echo "Logging in..."
TOKEN=$(http POST $BASE_URL/api/login \
  email=apitest@example.com \
  password=TestPass123! \
  | jq -r '.token')

echo "Token received: ${TOKEN:0:20}..."

# Test authenticated endpoints
echo "Listing documents..."
http GET $BASE_URL/api/list-documents \
  "Authorization: Bearer $TOKEN"

echo "API tests completed!"
```

Run the test script:

```bash
chmod +x test_api.sh
./test_api.sh
```

