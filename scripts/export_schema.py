#!/usr/bin/env python3
"""
scripts/export_schema.py — Export the PeerGlass OpenAPI schema to openapi.json.

Usage:
    python scripts/export_schema.py
    python scripts/export_schema.py --output /tmp/schema.json
"""
import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> None:
    parser = argparse.ArgumentParser(description="Export PeerGlass OpenAPI schema")
    parser.add_argument("--output", default="openapi.json", help="Output file path")
    args = parser.parse_args()

    from api import app
    schema = app.openapi()
    with open(args.output, "w") as f:
        json.dump(schema, f, indent=2)

    path_count = len(schema.get("paths", {}))
    print(f"Exported OpenAPI schema: {path_count} paths -> {args.output}")


if __name__ == "__main__":
    main()
