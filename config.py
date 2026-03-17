"""
config.py — PeerGlass configuration via environment variables.

All tuneable parameters can be overridden at runtime:
  PEERGLASS_TTL_BGP=60           Override BGP cache TTL in seconds
  PEERGLASS_TTL_RPKI=60          Override RPKI cache TTL
  PEERGLASS_TIMEOUT=10           Override HTTP request timeout
  PEERGLASS_GEOIP_DB=path        Path to MaxMind GeoLite2-City.mmdb
  PEERGLASS_RIPE_ATLAS_KEY=key   RIPE Atlas API key
  PEERGLASS_ALLOWED_ORIGINS=...  Comma-separated CORS origins
"""
import os


def get_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (ValueError, TypeError):
        return default


def get_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (ValueError, TypeError):
        return default


def get_str(name: str, default: str) -> str:
    return os.environ.get(name, default)


# Expose commonly-read config values
GEOIP_DB        = get_str("PEERGLASS_GEOIP_DB", "")
ATLAS_API_KEY   = get_str("PEERGLASS_RIPE_ATLAS_KEY", "")
