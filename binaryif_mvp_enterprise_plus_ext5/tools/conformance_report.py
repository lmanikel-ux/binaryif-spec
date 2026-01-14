
"""Runs a deterministic conformance suite and prints a single PASS/FAIL line.
This script is designed for insurer demos and audit packets.
"""
import json, subprocess, sys, os
import pytest

def main():
    # Run pytest and capture outcome
    code = pytest.main(["-q"])
    if code == 0:
        print("BINARYIF_CONFORMANCE: PASS")
        raise SystemExit(0)
    print("BINARYIF_CONFORMANCE: FAIL")
    raise SystemExit(1)

if __name__ == "__main__":
    main()
