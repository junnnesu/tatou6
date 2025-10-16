"""simple_text_watermark.py

Simple text watermarking technique: Add text watermark at the end of PDF

This example does not depend on any third-party libraries, only uses Python standard library.
It demonstrates how to create a basic watermarking technique.
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


class SimpleTextWatermark(WatermarkingMethod):
    """Simple text watermarking technique"""
    
    name: Final[str] = "simple-text-watermark"
    
    # Watermark markers
    _WATERMARK_MARKER: Final[str] = "%%TATOU-WATERMARK:v1"
    _SECRET_PREFIX: Final[str] = "%%SECRET:"
    
    @staticmethod
    def get_usage() -> str:
        return "Simple text watermarking technique that adds encrypted text watermark at the end of PDF. Applicable to all PDF documents."
    
    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Add text watermark at the end of PDF"""
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        
        # Load PDF data
        pdf_bytes = load_pdf_bytes(pdf)
        
        # Create encrypted watermark data
        encrypted_secret = self._encrypt_secret(secret, key)
        
        # Add watermark at the end of PDF
        watermark_data = f"\n{self._WATERMARK_MARKER}\n{self._SECRET_PREFIX}{encrypted_secret}\n"
        
        return pdf_bytes + watermark_data.encode('utf-8')
    
    def is_watermark_applicable(
        self,
        pdf,
        position: str | None = None,
    ) -> bool:
        """Check if applicable to this PDF"""
        try:
            # Try to load PDF data
            load_pdf_bytes(pdf)
            return True
        except Exception:
            return False
    
    def read_secret(self, pdf, key: str) -> str:
        """Read text watermark from PDF"""
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        
        try:
            pdf_bytes = load_pdf_bytes(pdf)
            pdf_text = pdf_bytes.decode('utf-8', errors='ignore')
            
            # Find watermark marker
            marker_pos = pdf_text.rfind(self._WATERMARK_MARKER)
            if marker_pos == -1:
                raise SecretNotFoundError("No watermark marker found")
            
            # Find secret data
            secret_pos = pdf_text.find(self._SECRET_PREFIX, marker_pos)
            if secret_pos == -1:
                raise SecretNotFoundError("No secret data found after marker")
            
            # Extract encrypted secret data
            secret_start = secret_pos + len(self._SECRET_PREFIX)
            secret_end = pdf_text.find('\n', secret_start)
            if secret_end == -1:
                secret_end = len(pdf_text)
            
            encrypted_secret = pdf_text[secret_start:secret_end].strip()
            if not encrypted_secret:
                raise SecretNotFoundError("Empty secret data")
            
            # Decrypt secret data
            secret = self._decrypt_secret(encrypted_secret, key)
            
            return secret
            
        except SecretNotFoundError:
            raise
        except Exception as e:
            raise WatermarkingError(f"Failed to read watermark: {str(e)}")
    
    def _encrypt_secret(self, secret: str, key: str) -> str:
        """Encrypt secret data"""
        # Use simple Base64 encoding and HMAC authentication
        secret_bytes = secret.encode('utf-8')
        
        # Create HMAC
        mac = hmac.new(key.encode('utf-8'), secret_bytes, hashlib.sha256)
        mac_hex = mac.hexdigest()
        
        # Combine data and MAC
        data = {
            "secret": base64.b64encode(secret_bytes).decode('ascii'),
            "mac": mac_hex,
            "version": "1.0"
        }
        
        # Return Base64 encoded JSON data
        return base64.urlsafe_b64encode(json.dumps(data).encode('utf-8')).decode('ascii')
    
    def _decrypt_secret(self, encrypted_data: str, key: str) -> str:
        """Decrypt secret data"""
        try:
            # Decode Base64 data
            json_data = base64.urlsafe_b64decode(encrypted_data.encode('ascii'))
            data = json.loads(json_data)
            
            # Extract secret and MAC
            secret_b64 = data["secret"]
            provided_mac = data["mac"]
            
            # Decode secret
            secret_bytes = base64.b64decode(secret_b64)
            
            # Verify MAC
            expected_mac = hmac.new(key.encode('utf-8'), secret_bytes, hashlib.sha256).hexdigest()
            
            if not hmac.compare_digest(provided_mac, expected_mac):
                raise InvalidKeyError("Invalid key for watermark decryption")
            
            return secret_bytes.decode('utf-8')
            
        except Exception as e:
            if isinstance(e, InvalidKeyError):
                raise
            raise SecretNotFoundError("Failed to decrypt watermark data")


__all__ = ["SimpleTextWatermark"]
