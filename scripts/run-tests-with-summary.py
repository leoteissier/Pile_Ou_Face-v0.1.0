#!/usr/bin/env python3
"""Exécute les tests Python et JavaScript, puis affiche un tableau récapitulatif."""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run_python_tests():
    """Lance les tests Python. Retourne (passed, failed, pending, exit_code, output)."""
    py = ROOT / "backends" / ".venv" / "bin" / "python"
    if not py.exists():
        py = ROOT / "backends" / ".venv" / "Scripts" / "python.exe"
    if not py.exists():
        py = Path("python3")
    run_tests = ROOT / "backends" / "static" / "tests" / "run_tests.py"
    result = subprocess.run(
        [str(py), str(run_tests)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    output = result.stdout + result.stderr
    # Parse: "Ran N tests in Xs" et "OK" ou "FAILED (failures=X, errors=Y)"
    passed = 0
    failed = 0
    match = re.search(r"Ran (\d+) test", output)
    if match:
        total = int(match.group(1))
        if "OK" in output:
            passed = total
            failed = 0
        else:
            fail_match = re.search(r"failures=(\d+)", output)
            err_match = re.search(r"errors=(\d+)", output)
            failed = (int(fail_match.group(1)) if fail_match else 0) + (
                int(err_match.group(1)) if err_match else 0
            )
            passed = total - failed
    return passed, failed, 0, result.returncode, output


def run_js_tests():
    """Lance les tests JavaScript. Retourne (passed, failed, pending, exit_code, output)."""
    result = subprocess.run(
        ["npm", "test"],
        cwd=ROOT / "extension",
        capture_output=True,
        text=True,
    )
    output = result.stdout + result.stderr
    # Parse: "N passing", "M failing", "K pending"
    passed = 0
    failed = 0
    pending = 0
    for line in output.splitlines():
        if m := re.search(r"(\d+)\s+passing", line):
            passed = int(m.group(1))
        if m := re.search(r"(\d+)\s+failing", line):
            failed = int(m.group(1))
        if m := re.search(r"(\d+)\s+pending", line):
            pending = int(m.group(1))
    return passed, failed, pending, result.returncode, output


def print_summary(py_results, js_results):
    """Affiche le tableau récapitulatif."""
    py_passed, py_failed, py_pending, _ = py_results[:4]
    js_passed, js_failed, js_pending, _ = js_results[:4]

    total_passed = py_passed + js_passed
    total_failed = py_failed + js_failed
    total_pending = py_pending + js_pending

    sep = "─" * 12
    print()
    print("┌" + "─" * 14 + "┬" + sep + "┬" + sep + "┬" + sep + "┐")
    print(
        "│ {:^12} │ {:^10} │ {:^10} │ {:^10} │".format(
            "Suite", "Réussis", "Échoués", "En attente"
        )
    )
    print("├" + "─" * 14 + "┼" + sep + "┼" + sep + "┼" + sep + "┤")
    print(
        "│ {:^12} │ {:^10} │ {:^10} │ {:^10} │".format(
            "Python", py_passed, py_failed, py_pending
        )
    )
    print(
        "│ {:^12} │ {:^10} │ {:^10} │ {:^10} │".format(
            "JavaScript", js_passed, js_failed, js_pending
        )
    )
    print("├" + "─" * 14 + "┼" + sep + "┼" + sep + "┼" + sep + "┤")
    print(
        "│ {:^12} │ {:^10} │ {:^10} │ {:^10} │".format(
            "Total", total_passed, total_failed, total_pending
        )
    )
    print("└" + "─" * 14 + "┴" + sep + "┴" + sep + "┴" + sep + "┘")


def main():
    print("Running Python tests...")
    py_results = run_python_tests()
    print(py_results[4], end="")
    if py_results[3] != 0:
        print("Python tests failed!")
    else:
        print("Python tests passed!")

    print("\nRunning JavaScript tests...")
    js_results = run_js_tests()
    print(js_results[4], end="")
    if js_results[3] != 0:
        print("JavaScript tests failed!")
    else:
        print("JavaScript tests passed!")

    print_summary(py_results, js_results)
    sys.exit(0 if py_results[3] == 0 and js_results[3] == 0 else 1)


if __name__ == "__main__":
    main()
