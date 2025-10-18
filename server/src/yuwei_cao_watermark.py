"""yuwei_cao_watermark.py

Yuwei Cao's watermarking method - Have a nice day!
"""

from __future__ import annotations
from typing import Final
import base64
import hashlib
import hmac
import json

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class YuweiCaoWatermark(WatermarkingMethod):
    """Yuwei Cao's watermarking method using EOF-based embedding."""

    name: Final[str] = "yuwei-cao-method"
    
    _MAGIC: Final[bytes] = b"\n% YuweiCao-Watermark:v1\n"
    _VERSION: Final[int] = 1
    _AUTHOR: Final[str] = "Yuwei Cao"
    
    @staticmethod
    def get_usage() -> str:
        return (
            "Yuwei Cao's watermarking method using encrypted EOF embedding. "
            "Embeds watermark after PDF EOF marker. Position is ignored."
        )
    
    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Add watermark by appending encrypted data after EOF."""
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        
        # Load PDF
        data = load_pdf_bytes(pdf)
        
        # Build encrypted payload
        try:
            payload = self._build_encrypted_payload(secret, key)
        except Exception as e:
            raise WatermarkingError(f"Failed to encrypt payload: {e}")
        
        # Append watermark
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        
        return out
    
    def is_watermark_applicable(
        self,
        pdf,
        position: str | None = None,
    ) -> bool:
        """Check if this method can be applied."""
        try:
            load_pdf_bytes(pdf)
            return True
        except Exception:
            return False
    
    def read_secret(self, pdf, key: str) -> str:
        """Extract and decrypt the secret from PDF."""
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        
        # Load PDF
        data = load_pdf_bytes(pdf)
        
        # Find watermark marker
        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No Yuwei Cao watermark found in document")
        
        # Extract payload
        start = idx + len(self._MAGIC)
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        payload_bytes = data[start:end].strip()
        
        if not payload_bytes:
            raise SecretNotFoundError("Found marker but payload is empty")
        
        # Decode and decrypt
        try:
            payload_str = payload_bytes.decode('ascii')
        except UnicodeDecodeError as e:
            raise SecretNotFoundError(f"Payload is not valid ASCII: {e}")
        
        try:
            return self._decrypt_payload(payload_str, key)
        except InvalidKeyError:
            raise  # Re-raise InvalidKeyError as-is
        except SecretNotFoundError:
            raise  # Re-raise SecretNotFoundError as-is
        except Exception as e:
            raise WatermarkingError(f"Unexpected error during decryption: {e}")
    
    def _build_encrypted_payload(self, secret: str, password: str) -> bytes:
        """Build encrypted payload."""
        secret_bytes = secret.encode('utf-8')
        
        # Derive key
        salt = b"YuweiCao2025"
        derived_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations=100000,
            dklen=32
        )
        
        # XOR encryption
        encrypted = bytearray()
        for i, byte in enumerate(secret_bytes):
            encrypted.append(byte ^ derived_key[i % len(derived_key)])
        
        # HMAC
        mac = hmac.new(
            password.encode('utf-8'),
            bytes(encrypted),
            hashlib.sha256
        ).hexdigest()
        
        # Build payload
        payload_obj = {
            "v": self._VERSION,
            "author": self._AUTHOR,
            "data": base64.b64encode(bytes(encrypted)).decode('ascii'),
            "mac": mac
        }
        
        payload_json = json.dumps(payload_obj, separators=(',', ':')).encode('utf-8')
        return base64.urlsafe_b64encode(payload_json)
    
    def _decrypt_payload(self, payload: str, password: str) -> str:
        """Decrypt the payload and return the secret."""
        # Step 1: Decode base64url
        try:
            payload_json_bytes = base64.urlsafe_b64decode(payload)
        except Exception as e:
            raise SecretNotFoundError(f"Failed to decode base64url payload: {e}")
        
        # Step 2: Parse JSON
        try:
            payload_obj = json.loads(payload_json_bytes)
        except json.JSONDecodeError as e:
            raise SecretNotFoundError(f"Payload is not valid JSON: {e}")
        
        # Step 3: Validate structure
        if not isinstance(payload_obj, dict):
            raise SecretNotFoundError("Payload is not a JSON object")
        
        if payload_obj.get("v") != self._VERSION:
            raise SecretNotFoundError(f"Unsupported version: {payload_obj.get('v')}")
        
        if payload_obj.get("author") != self._AUTHOR:
            raise SecretNotFoundError(f"Wrong author: {payload_obj.get('author')}")
        
        # Step 4: Extract fields
        try:
            data_b64 = payload_obj["data"]
            stored_mac = payload_obj["mac"]
        except KeyError as e:
            raise SecretNotFoundError(f"Missing required field: {e}")
        
        # Step 5: Decode encrypted data
        try:
            encrypted = base64.b64decode(data_b64)
        except Exception as e:
            raise SecretNotFoundError(f"Failed to decode encrypted data: {e}")
        
        # Step 6: Derive key
        salt = b"YuweiCao2025"
        derived_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations=100000,
            dklen=32
        )
        
        # Step 7: Verify MAC
        expected_mac = hmac.new(
            password.encode('utf-8'),
            encrypted,
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(stored_mac, expected_mac):
            raise InvalidKeyError("MAC verification failed - incorrect password")
        
        # Step 8: Decrypt
        decrypted = bytearray()
        for i, byte in enumerate(encrypted):
            decrypted.append(byte ^ derived_key[i % len(derived_key)])
        
        # Step 9: Decode UTF-8
        try:
            return bytes(decrypted).decode('utf-8')
        except UnicodeDecodeError as e:
            raise WatermarkingError(f"Decrypted data is not valid UTF-8: {e}")


__all__ = ["YuweiCaoWatermark"]