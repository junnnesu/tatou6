"""yuwei_cao_watermark.py

Yuwei Cao's watermarking method - Fixed version based on Yuyuan Su's working pattern.
Uses EOF-based watermarking like the working methods in the project.
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
    """
    Yuwei Cao's watermarking method using EOF-based embedding.
    
    Similar approach to Yuyuan Su's method for maximum reliability.
    Embeds encrypted watermark after the PDF EOF marker.
    """

    name: Final[str] = "yuwei-cao-method"
    
    # Constants - Similar to Yuyuan's approach
    _MAGIC: Final[bytes] = b"\n% YuweiCao-Watermark:v1\n"
    _VERSION: Final[int] = 1
    _AUTHOR: Final[str] = "Yuwei Cao"
    
    @staticmethod
    def get_usage() -> str:
        return (
            "Yuwei Cao's watermarking method using encrypted EOF embedding. "
            "Embeds watermark after PDF EOF marker. Position is ignored. "
            "Simple and reliable."
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
        
        # Append watermark after EOF (same pattern as Yuyuan's method)
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
            data = load_pdf_bytes(pdf)
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
            raise SecretNotFoundError("No Yuwei Cao watermark found")
        
        # Extract payload
        start = idx + len(self._MAGIC)
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        payload = data[start:end].strip()
        
        if not payload:
            raise SecretNotFoundError("Found marker but empty payload")
        
        # Decrypt and return
        try:
            return self._decrypt_payload(payload.decode('ascii'), key)
        except UnicodeDecodeError as e:
            raise SecretNotFoundError(f"Invalid payload encoding: {e}")
    
    # ===== Encryption/Decryption Methods =====
    
    def _build_encrypted_payload(self, secret: str, password: str) -> bytes:
        """
        Build encrypted payload similar to Yuyuan's approach.
        
        Format (base64url encoded):
        {
            "v": 1,
            "author": "Yuwei Cao",
            "data": "<base64_encrypted_data>",
            "mac": "<hex_mac>"
        }
        """
        secret_bytes = secret.encode('utf-8')
        
        # Derive encryption key using PBKDF2 (similar to Yuyuan)
        salt = b"YuweiCao2025"  # Fixed salt
        derived_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations=100000,
            dklen=32
        )
        
        # XOR encryption (simple but effective)
        encrypted = bytearray()
        for i, byte in enumerate(secret_bytes):
            encrypted.append(byte ^ derived_key[i % len(derived_key)])
        
        # Create HMAC for authentication
        mac = hmac.new(
            password.encode('utf-8'),
            encrypted,
            hashlib.sha256
        ).hexdigest()
        
        # Build payload object
        payload_obj = {
            "v": self._VERSION,
            "author": self._AUTHOR,
            "data": base64.b64encode(encrypted).decode('ascii'),
            "mac": mac
        }
        
        # Encode as base64url for PDF compatibility
        payload_json = json.dumps(payload_obj, separators=(',', ':')).encode('utf-8')
        return base64.urlsafe_b64encode(payload_json)
    
    def _decrypt_payload(self, payload: str, password: str) -> str:
        """Decrypt the payload and return the secret."""
        try:
            # Decode base64url
            payload_json = base64.urlsafe_b64decode(payload)
            payload_obj = json.loads(payload_json)
        except Exception as e:
            raise SecretNotFoundError(f"Malformed watermark payload: {e}")
        
        # Validate version
        if payload_obj.get("v") != self._VERSION:
            raise SecretNotFoundError("Unsupported watermark version")
        
        # Validate author
        if payload_obj.get("author") != self._AUTHOR:
            raise SecretNotFoundError("Wrong author signature")
        
        try:
            # Extract components
            encrypted = base64.b64decode(payload_obj["data"])
            stored_mac = payload_obj["mac"]
        except (KeyError, ValueError) as e:
            raise SecretNotFoundError(f"Invalid payload fields: {e}")
        
        # Derive decryption key
        salt = b"YuweiCao2025"
        derived_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations=100000,
            dklen=32
        )
        
        # Verify MAC
        expected_mac = hmac.new(
            password.encode('utf-8'),
            encrypted,
            hashlib.sha256
        ).hexdigest()
        
        if stored_mac != expected_mac:
            raise InvalidKeyError("MAC verification failed - incorrect key")
        
        # Decrypt using XOR
        decrypted = bytearray()
        for i, byte in enumerate(encrypted):
            decrypted.append(byte ^ derived_key[i % len(derived_key)])
        
        return decrypted.decode('utf-8')


__all__ = ["YuweiCaoWatermark"]