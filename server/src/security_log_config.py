# server/src/security_log_config.py
import logging
import os
from pathlib import Path

def setup_security_logging():
    """Setup security logging configuration"""
    log_dir = Path("/app/logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Configure security logger
    security_logger = logging.getLogger('security')
    security_handler = logging.FileHandler(log_dir / 'security.log')
    security_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    security_logger.addHandler(security_handler)
    security_logger.setLevel(logging.INFO)
    
    security_handler.flush()
    
    return security_logger