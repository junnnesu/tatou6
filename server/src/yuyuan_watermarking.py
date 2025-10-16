"""watermarking_yuyuan.py

Secure watermarking method using encrypted PDF comment embedding.

This method embeds encrypted watermarks into PDF comments, making them:
1. More secure than plaintext (uses AES-256-GCM encryption)
2. Authenticated using built-in GCM authentication
3. Hidden in PDF structure using comment syntax
4. Harder to detect than simple EOF appending

Design:
-------
- Uses AES-256-GCM for authenticated encryption
- Encrypts secret using password-derived key (PBKDF2)
- Embeds encrypted data as PDF comment after EOF
- Uses base64 encoding to ensure PDF compatibility
"""
from __future__ import annotations

from typing import Final
import base64
import hashlib
import hmac
import json
import secrets
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
)


class WatermarkSafe(WatermarkingMethod):
    """Secure watermarking using encrypted PDF comments.
    
    This method:
    1. Derives a 256-bit key from the user-provided password using PBKDF2
    2. Encrypts the secret using AES-256-GCM
    3. Embeds the encrypted data as a PDF comment after EOF
    4. Uses base64 encoding for PDF compatibility
    
    The watermark is stored as a PDF comment that looks like metadata,
    making it harder to detect than simple plaintext appending.
    """

    name: Final[str] = "watermark_safe"

    # Constants
    _MAGIC: Final[bytes] = b"\n% WM-SAFE:v1\n"
    _VERSION: Final[int] = 1
    _KDF_ITERATIONS: Final[int] = 100000  # PBKDF2 iterations
    _KEY_LENGTH: Final[int] = 32  # 256 bits
    
    # ---------------------
    # Public API overrides
    # ---------------------
    
    @staticmethod
    def get_usage() -> str:
        return (
            "Secure watermarking using AES-256-GCM encrypted PDF comments. "
            "Embeds encrypted watermarks after PDF EOF marker. Position is ignored. "
            "Provides confidentiality and integrity protection."
        )

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Embed an encrypted watermark into the PDF as a comment.
        
        Steps:
        1. Load PDF bytes
        2. Derive encryption key from password using PBKDF2
        3. Encrypt secret using AES-256-GCM
        4. Append encrypted data as PDF comment
        5. Return modified PDF bytes
        """
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

        # Append watermark as PDF comment
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        
        return out
        
    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        """Check if this method can be applied to the given PDF."""
        try:
            data = load_pdf_bytes(pdf)
            return True
        except Exception:
            return False

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        """Extract and decrypt the secret from the PDF.
        
        Steps:
        1. Load PDF and find watermark comment
        2. Extract encrypted payload
        3. Derive decryption key from password using PBKDF2
        4. Decrypt using AES-256-GCM and verify
        5. Return plaintext secret
        """
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        # Load PDF
        data = load_pdf_bytes(pdf)
        
        # Find watermark marker
        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No watermark_safe watermark found")

        # Extract payload
        start = idx + len(self._MAGIC)
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        payload = data[start:end].strip()
        
        if not payload:
            raise SecretNotFoundError("Found marker but empty payload")

        # Decrypt and return secret
        try:
            return self._decrypt_payload(payload.decode('ascii'), key)
        except UnicodeDecodeError as e:
            raise SecretNotFoundError(f"Invalid payload encoding: {e}")

    # ---------------------
    # Internal helpers
    # ---------------------

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a 256-bit encryption key from password using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self._KEY_LENGTH,
            salt=salt,
            iterations=self._KDF_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    def _build_encrypted_payload(self, secret: str, password: str) -> bytes:
        """Build an encrypted payload from the secret.
        
        Format (base64url encoded):
        {
            "v": 1,
            "salt": "<hex>",
            "nonce": "<hex>",
            "ct": "<hex>"
        }
        """
        secret_bytes = secret.encode('utf-8')
        
        # Generate random salt and nonce
        salt = secrets.token_bytes(16)  # 128 bits
        nonce = secrets.token_bytes(12)  # 96 bits for GCM
        
        # Derive encryption key
        encryption_key = self._derive_key(password, salt)
        
        # Encrypt using AES-256-GCM
        aesgcm = AESGCM(encryption_key)
        ciphertext = aesgcm.encrypt(nonce, secret_bytes, None)
        
        # Build payload (ciphertext includes auth tag at end)
        payload_obj = {
            "v": self._VERSION,
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "ct": ciphertext.hex()
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
        
        try:
            # Extract components
            salt = bytes.fromhex(payload_obj["salt"])
            nonce = bytes.fromhex(payload_obj["nonce"])
            ciphertext = bytes.fromhex(payload_obj["ct"])
        except (KeyError, ValueError) as e:
            raise SecretNotFoundError(f"Invalid payload fields: {e}")
        
        # Derive decryption key
        try:
            decryption_key = self._derive_key(password, salt)
        except Exception as e:
            raise InvalidKeyError(f"Key derivation failed: {e}")
        
        # Decrypt using AES-256-GCM (includes authentication)
        try:
            aesgcm = AESGCM(decryption_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise InvalidKeyError("Decryption failed - incorrect key or corrupted data")
        
        return plaintext.decode('utf-8')


__all__ = ["WatermarkSafe"]
