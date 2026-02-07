"""Logging helpers for the honeypot."""
import logging
import os

LOG_PATH = "/app/logs/honeypot.log"

# extracted from honeypot.py started code
def create_logger():
    os.makedirs("/app/logs", exist_ok=True)
    logger = logging.getLogger("Honeypot")
    logger.setLevel(logging.INFO)
    
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )
    
    file_handler = logging.FileHandler(LOG_PATH)
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    return logger


