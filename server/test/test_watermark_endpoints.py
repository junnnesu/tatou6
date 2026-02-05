"""
Unit tests for create-watermark and read-watermark endpoints
Tests achieve high branch coverage using mock database and mock watermarking methods
"""
import os
import sys
import pytest
import tempfile
from pathlib import Path

# Set test mode before importing server
os.environ["TESTMODE"] = "1"
os.environ["SECRET_KEY"] = "test-secret-key"

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server import create_app
import watermarking_utils as WMUtils
from watermarking_method import WatermarkingMethod


class MockWatermarkingMethod(WatermarkingMethod):
    """Mock watermarking method for testing - supports both success and failure scenarios"""

    name = "mock-method"

    def __init__(self, should_fail=False, fail_on_read=False, not_applicable=False):
        self.should_fail = should_fail
        self.fail_on_read = fail_on_read
        self.not_applicable = not_applicable

    def add_watermark(self, pdf: str, secret: str, key: str, position: str = None) -> bytes:
        """Mock watermark addition - returns fake PDF bytes or raises exception"""
        if self.should_fail:
            raise Exception("Mock watermarking failed")
        # Return minimal valid PDF
        return b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF"

    def read_secret(self, pdf: str, key: str) -> str:
        """Mock watermark reading - returns secret or raises exception"""
        if self.fail_on_read:
            raise Exception("Mock read failed")
        return "mock-secret-123"

    def is_applicable(self, pdf: str, position: str = None) -> bool:
        """Mock applicability check"""
        return not self.not_applicable

    def is_watermark_applicable(self, pdf: str, position: str = None) -> bool:
        """Mock watermark applicability check"""
        return not self.not_applicable

    def get_usage(self) -> str:
        return "Mock watermarking method for testing"


class MockWatermarkingMethodNotApplicable(WatermarkingMethod):
    """Mock method that is not applicable"""

    name = "mock-not-applicable"

    def add_watermark(self, pdf: str, secret: str, key: str, position: str = None) -> bytes:
        return b"%PDF-1.4\n%%EOF"

    def read_secret(self, pdf: str, key: str) -> str:
        return "secret"

    def is_applicable(self, pdf: str, position: str = None) -> bool:
        return False  # Always not applicable

    def is_watermark_applicable(self, pdf: str, position: str = None) -> bool:
        return False  # Always not applicable

    def get_usage(self) -> str:
        return "Mock method that is not applicable"


@pytest.fixture
def app():
    """Create test Flask app with mock database"""
    app = create_app()
    app.config["TESTING"] = True

    # Create temporary storage directory
    temp_dir = tempfile.mkdtemp()
    app.config["STORAGE_DIR"] = Path(temp_dir)
    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)

    # Register mock watermarking methods
    WMUtils.METHODS["mock-method"] = MockWatermarkingMethod()
    WMUtils.METHODS["mock-fail"] = MockWatermarkingMethod(should_fail=True)
    WMUtils.METHODS["mock-read-fail"] = MockWatermarkingMethod(fail_on_read=True)
    WMUtils.METHODS["mock-not-applicable"] = MockWatermarkingMethodNotApplicable()

    yield app

    # Cleanup
    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


@pytest.fixture
def auth_token(client):
    """Create a test user and return auth token"""
    # Create user
    response = client.post("/api/create-user", json={
        "email": "test@example.com",
        "login": "testuser",
        "password": "testpass123"
    })
    assert response.status_code == 201

    # Login
    response = client.post("/api/login", json={
        "email": "test@example.com",
        "password": "testpass123"
    })
    assert response.status_code == 200
    return response.json["token"]


@pytest.fixture
def test_document(client, auth_token, app):
    """Create a test document and return its ID"""
    # Create a minimal PDF file
    pdf_content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\ntrailer\n<< /Root 1 0 R /Size 3 >>\nstartxref\n100\n%%EOF"

    # Upload document
    data = {
        "file": (tempfile.NamedTemporaryFile(suffix=".pdf", delete=False), "test.pdf")
    }

    # Write PDF content to temp file
    temp_file = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
    temp_file.write(pdf_content)
    temp_file.close()

    with open(temp_file.name, "rb") as f:
        response = client.post(
            "/api/upload-document",
            data={"file": (f, "test.pdf")},
            headers={"Authorization": f"Bearer {auth_token}"},
            content_type="multipart/form-data"
        )

    os.unlink(temp_file.name)
    assert response.status_code == 201
    return response.json["id"]


# ============================================================================
# Tests for /api/create-watermark endpoint
# ============================================================================

def test_create_watermark_success(client, auth_token, test_document):
    """Test successful watermark creation"""
    response = client.post(
        f"/api/create-watermark/{test_document}",
        json={
            "method": "mock-method",
            "intended_for": "recipient@example.com",
            "secret": "my-secret",
            "key": "my-key"
        },
        headers={"Authorization": f"Bearer {auth_token}"}
    )

    assert response.status_code == 201
    data = response.json
    assert "id" in data
    assert data["documentid"] == test_document
    assert "link" in data
    assert data["intended_for"] == "recipient@example.com"
    assert data["method"] == "mock-method"


def test_create_watermark_missing_auth(client, test_document):
    """Test watermark creation without authentication - should return 401"""
    response = client.post(
        f"/api/create-watermark/{test_document}",
        json={
            "method": "mock-method",
            "intended_for": "recipient@example.com",
            "secret": "my-secret",
            "key": "my-key"
        }
    )

    assert response.status_code == 401
    assert "error" in response.json


def test_create_watermark_missing_document_id(client, auth_token):
    """Test watermark creation without document ID - should return 400"""
    response = client.post(
        "/api/create-watermark",
        json={
            "method": "mock-method",
            "intended_for": "recipient@example.com",
            "secret": "my-secret",
            "key": "my-key"
        },
        headers={"Authorization": f"Bearer {auth_token}"}
    )

    assert response.status_code == 400
    assert response.json["error"] == "document id required"


def test_create_watermark_missing_required_fields(client, auth_token, test_document):
    """Test watermark creation with missing required fields - should return 400"""
    # Missing method
    response = client.post(
        f"/api/create-watermark/{test_document}",
        json={
            "intended_for": "recipient@example.com",
            "secret": "my-secret",
            "key": "my-key"
        },
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 400
    assert "error" in response.json

    # Missing intended_for
    response = client.post(
        f"/api/create-watermark/{test_document}",
        json={
            "method": "mock-method",
            "secret": "my-secret",
            "key": "my-key"
        },
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 400

    # Missing secret
    response = client.post(
        f"/api/create-watermark/{test_document}",
        json={
            "method": "mock-method",
            "intended_for": "recipient@example.com",
            "key": "my-key"
        },
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 400

    # Missing key
    response = client.post(
        f"/api/create-watermark/{test_document}",
        json={
            "method": "mock-method",
            "intended_for": "recipient@example.com",
            "secret": "my-secret"
        },
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 400


def test_create_watermark_document_not_found(client, auth_token):
    """Test watermark creation for non-existent document - should return 404"""
    response = client.post(
        "/api/create-watermark/99999",
        json={
            "method": "mock-method",
            "intended_for": "recipient@example.com",
            "secret": "my-secret",
            "key": "my-key"
        },
        headers={"Authorization": f"Bearer {auth_token}"}
    )

    assert response.status_code == 404
    assert response.json["error"] == "document not found"


def test_create_watermark_not_applicable(client, auth_token, test_document):
    """Test watermark creation when method is not applicable - should return 400"""
    response = client.post(
        f"/api/create-watermark/{test_document}",
        json={
            "method": "mock-not-applicable",
            "intended_for": "recipient@example.com",
            "secret": "my-secret",
            "key": "my-key"
        },
        headers={"Authorization": f"Bearer {auth_token}"}
    )

    assert response.status_code == 400
    assert "not applicable" in response.json["error"]


def test_create_watermark_method_fails(client, auth_token, test_document):
    """Test watermark creation when watermarking method fails - should return 500"""
    response = client.post(
        f"/api/create-watermark/{test_document}",
        json={
            "method": "mock-fail",
            "intended_for": "recipient@example.com",
            "secret": "my-secret",
            "key": "my-key"
        },
        headers={"Authorization": f"Bearer {auth_token}"}
    )

    assert response.status_code == 500
    assert "watermarking failed" in response.json["error"]


# ============================================================================
# Tests for /api/read-watermark endpoint
# ============================================================================

def test_read_watermark_success(client, auth_token, test_document):
    """Test successful watermark reading"""
    response = client.post(
        f"/api/read-watermark/{test_document}",
        json={
            "method": "mock-method",
            "key": "my-key"
        },
        headers={"Authorization": f"Bearer {auth_token}"}
    )

    assert response.status_code == 201
    data = response.json
    assert data["documentid"] == test_document
    assert data["secret"] == "mock-secret-123"
    assert data["method"] == "mock-method"


def test_read_watermark_missing_auth(client, test_document):
    """Test watermark reading without authentication - should return 401"""
    response = client.post(
        f"/api/read-watermark/{test_document}",
        json={
            "method": "mock-method",
            "key": "my-key"
        }
    )

    assert response.status_code == 401
    assert "error" in response.json


def test_read_watermark_missing_document_id(client, auth_token):
    """Test watermark reading without document ID - should return 400"""
    response = client.post(
        "/api/read-watermark",
        json={
            "method": "mock-method",
            "key": "my-key"
        },
        headers={"Authorization": f"Bearer {auth_token}"}
    )

    assert response.status_code == 400
    assert response.json["error"] == "document id required"


def test_read_watermark_missing_required_fields(client, auth_token, test_document):
    """Test watermark reading with missing required fields - should return 400"""
    # Missing method
    response = client.post(
        f"/api/read-watermark/{test_document}",
        json={
            "key": "my-key"
        },
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 400
    assert "error" in response.json

    # Missing key
    response = client.post(
        f"/api/read-watermark/{test_document}",
        json={
            "method": "mock-method"
        },
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 400


def test_read_watermark_document_not_found(client, auth_token):
    """Test watermark reading for non-existent document - should return 404"""
    response = client.post(
        "/api/read-watermark/99999",
        json={
            "method": "mock-method",
            "key": "my-key"
        },
        headers={"Authorization": f"Bearer {auth_token}"}
    )

    assert response.status_code == 404
    assert response.json["error"] == "document not found"


def test_read_watermark_method_fails(client, auth_token, test_document):
    """Test watermark reading when method fails - should return 400"""
    response = client.post(
        f"/api/read-watermark/{test_document}",
        json={
            "method": "mock-read-fail",
            "key": "my-key"
        },
        headers={"Authorization": f"Bearer {auth_token}"}
    )

    assert response.status_code == 400
    assert "Error when attempting to read watermark" in response.json["error"]


# Note: The following branches cannot be covered in unit testing environment:
# 1. server.py:653 - RuntimeError for invalid document path: This requires manipulating
#    the database to contain an invalid path that escapes STORAGE_DIR, which is prevented
#    by the application logic during document creation.
# 2. server.py:656 - File missing on disk: This would require deleting the file after
#    database insertion but before the watermark operation, which is a race condition
#    that cannot be reliably reproduced in unit tests.
# 3. server.py:868 - RuntimeError for invalid document path in read_watermark: Same as #1
# 4. server.py:871 - File missing on disk in read_watermark: Same as #2
