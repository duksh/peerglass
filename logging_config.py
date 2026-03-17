"""
logging_config.py — Structured JSON logging for PeerGlass.

Usage:
    from logging_config import get_logger
    logger = get_logger("peerglass.tool")
    logger.info("cache hit", extra={"tool": "rir_query_ip", "resource": "1.1.1.1", "cache": "hit"})
"""
import logging
import json
import time


class _JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts":         self.formatTime(record, "%Y-%m-%dT%H:%M:%SZ"),
            "level":      record.levelname,
            "logger":     record.name,
            "msg":        record.getMessage(),
        }
        for field in ("tool", "resource", "cache", "latency_ms", "status"):
            val = getattr(record, field, None)
            if val is not None:
                payload[field] = val
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def get_logger(name: str = "peerglass") -> logging.Logger:
    """Return a structured JSON logger for PeerGlass."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(_JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
