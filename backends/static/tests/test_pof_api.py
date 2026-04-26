"""Tests for the pof scripting API module."""

import subprocess, os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
PYTHON = os.path.join(ROOT, "backends", ".venv", "bin", "python3")
BINARY = os.path.join(ROOT, "examples", "demo_analysis.elf")


def test_pof_symbols():
    """pof.symbols() returns a list with at least one symbol."""
    code = f"""
import sys; sys.path.insert(0, '{ROOT}')
from backends.static.pof import symbols
result = symbols('{BINARY}')
assert isinstance(result, dict), f'expected dict, got {{type(result)}}'
assert result.get('ok') is True, f'not ok: {{result.get("error")}}'
print('PASS')
"""
    r = subprocess.run([PYTHON, "-c", code], capture_output=True, text=True, timeout=30)
    assert "PASS" in r.stdout, f"stdout={r.stdout} stderr={r.stderr}"


def test_pof_info():
    """pof.info() returns binary info."""
    code = f"""
import sys; sys.path.insert(0, '{ROOT}')
from backends.static.pof import info
result = info('{BINARY}')
assert isinstance(result, dict)
assert result.get('ok') is True
print('PASS')
"""
    r = subprocess.run([PYTHON, "-c", code], capture_output=True, text=True, timeout=30)
    assert "PASS" in r.stdout, f"stdout={r.stdout} stderr={r.stderr}"


def test_pof_strings():
    """pof.strings() returns extracted strings."""
    code = f"""
import sys; sys.path.insert(0, '{ROOT}')
from backends.static.pof import strings
result = strings('{BINARY}')
assert isinstance(result, dict)
assert result.get('ok') is True
print('PASS')
"""
    r = subprocess.run([PYTHON, "-c", code], capture_output=True, text=True, timeout=30)
    assert "PASS" in r.stdout, f"stdout={r.stdout} stderr={r.stderr}"
