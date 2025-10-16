"""simple_text_watermark.py

简单文本水印技术：在PDF末尾添加文本水印

这个示例不依赖任何第三方库，只使用Python标准库。
它演示了如何创建一个基本的水印技术。
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
    """简单的文本水印技术"""
    
    name: Final[str] = "simple-text-watermark"
    
    # 水印标记
    _WATERMARK_MARKER: Final[str] = "%%TATOU-WATERMARK:v1"
    _SECRET_PREFIX: Final[str] = "%%SECRET:"
    
    @staticmethod
    def get_usage() -> str:
        return "简单的文本水印技术，在PDF末尾添加加密的文本水印。适用于所有PDF文档。"
    
    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """在PDF末尾添加文本水印"""
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        
        # 加载PDF数据
        pdf_bytes = load_pdf_bytes(pdf)
        
        # 创建加密的水印数据
        encrypted_secret = self._encrypt_secret(secret, key)
        
        # 在PDF末尾添加水印
        watermark_data = f"\n{self._WATERMARK_MARKER}\n{self._SECRET_PREFIX}{encrypted_secret}\n"
        
        return pdf_bytes + watermark_data.encode('utf-8')
    
    def is_watermark_applicable(
        self,
        pdf,
        position: str | None = None,
    ) -> bool:
        """检查是否适用于此PDF"""
        try:
            # 尝试加载PDF数据
            load_pdf_bytes(pdf)
            return True
        except Exception:
            return False
    
    def read_secret(self, pdf, key: str) -> str:
        """从PDF中读取文本水印"""
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        
        try:
            pdf_bytes = load_pdf_bytes(pdf)
            pdf_text = pdf_bytes.decode('utf-8', errors='ignore')
            
            # 查找水印标记
            marker_pos = pdf_text.rfind(self._WATERMARK_MARKER)
            if marker_pos == -1:
                raise SecretNotFoundError("No watermark marker found")
            
            # 查找秘密数据
            secret_pos = pdf_text.find(self._SECRET_PREFIX, marker_pos)
            if secret_pos == -1:
                raise SecretNotFoundError("No secret data found after marker")
            
            # 提取加密的秘密数据
            secret_start = secret_pos + len(self._SECRET_PREFIX)
            secret_end = pdf_text.find('\n', secret_start)
            if secret_end == -1:
                secret_end = len(pdf_text)
            
            encrypted_secret = pdf_text[secret_start:secret_end].strip()
            if not encrypted_secret:
                raise SecretNotFoundError("Empty secret data")
            
            # 解密秘密数据
            secret = self._decrypt_secret(encrypted_secret, key)
            
            return secret
            
        except SecretNotFoundError:
            raise
        except Exception as e:
            raise WatermarkingError(f"读取水印失败: {str(e)}")
    
    def _encrypt_secret(self, secret: str, key: str) -> str:
        """加密秘密数据"""
        # 使用简单的Base64编码和HMAC认证
        secret_bytes = secret.encode('utf-8')
        
        # 创建HMAC
        mac = hmac.new(key.encode('utf-8'), secret_bytes, hashlib.sha256)
        mac_hex = mac.hexdigest()
        
        # 组合数据和MAC
        data = {
            "secret": base64.b64encode(secret_bytes).decode('ascii'),
            "mac": mac_hex,
            "version": "1.0"
        }
        
        # 返回Base64编码的JSON数据
        return base64.urlsafe_b64encode(json.dumps(data).encode('utf-8')).decode('ascii')
    
    def _decrypt_secret(self, encrypted_data: str, key: str) -> str:
        """解密秘密数据"""
        try:
            # 解码Base64数据
            json_data = base64.urlsafe_b64decode(encrypted_data.encode('ascii'))
            data = json.loads(json_data)
            
            # 提取secret和MAC
            secret_b64 = data["secret"]
            provided_mac = data["mac"]
            
            # 解码secret
            secret_bytes = base64.b64decode(secret_b64)
            
            # 验证MAC
            expected_mac = hmac.new(key.encode('utf-8'), secret_bytes, hashlib.sha256).hexdigest()
            
            if not hmac.compare_digest(provided_mac, expected_mac):
                raise InvalidKeyError("Invalid key for watermark decryption")
            
            return secret_bytes.decode('utf-8')
            
        except Exception as e:
            if isinstance(e, InvalidKeyError):
                raise
            raise SecretNotFoundError("Failed to decrypt watermark data")


__all__ = ["SimpleTextWatermark"]
