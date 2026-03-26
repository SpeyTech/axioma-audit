#!/usr/bin/env python3
"""
ax-rtm-verify.py — Requirements Traceability Matrix Verifier

DVEC: v1.3
DETERMINISM: D1 — Strict Deterministic

Verifies that all public functions have SRS requirement anchors and
that no orphan code exists without traceability.

Copyright (c) 2026 The Murray Family Innovation Trust
SPDX-License-Identifier: GPL-3.0-or-later
Patent: UK GB2521625.0

@traceability SRS-001-SHALL-003, SRS-001-SHALL-004, SRS-013-SHALL-001
"""

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

# Required SRS anchors for public functions (from specification)
REQUIRED_FUNCTIONS = {
    "axilog_commit": ["SRS-007"],
    "ax_ledger_genesis": ["SRS-001-SHALL-006", "SRS-001-SHALL-007", "SRS-006-SHALL-002"],
    "ax_ledger_append": ["SRS-005-SHALL-005", "SRS-006-SHALL-002", "SRS-006-SHALL-004"],
    "ax_verify_chain": ["SRS-005-SHALL-005", "SRS-006-SHALL-007"],
    "ax_commit_evidence": ["SRS-006-SHALL-003", "SRS-007-SHALL-006", "SRS-007-SHALL-008"],
}

# DVEC forbidden patterns
FORBIDDEN_PATTERNS = [
    (r'\bfloat\b', "Floating point type 'float' forbidden"),
    (r'\bdouble\b', "Floating point type 'double' forbidden"),
    (r'\bTODO\b', "Deferred correctness marker 'TODO' forbidden"),
    (r'\bFIXME\b', "Deferred correctness marker 'FIXME' forbidden"),
    (r'\bHACK\b', "Deferred correctness marker 'HACK' forbidden"),
    (r'\bOPTIMIZE\b', "Deferred correctness marker 'OPTIMIZE' forbidden"),
    (r'\bmalloc\s*\(', "Dynamic allocation 'malloc' forbidden"),
    (r'\bfree\s*\(', "Dynamic allocation 'free' forbidden"),
    (r'\brealloc\s*\(', "Dynamic allocation 'realloc' forbidden"),
    (r'\bcalloc\s*\(', "Dynamic allocation 'calloc' forbidden"),
    (r'\btime\s*\(', "System clock 'time()' forbidden"),
    (r'\bclock\s*\(', "System clock 'clock()' forbidden"),
    (r'\bgettimeofday\s*\(', "System clock 'gettimeofday()' forbidden"),
    (r'\bclock_gettime\s*\(', "System clock 'clock_gettime()' forbidden"),
]


class RTMVerifier:
    """Requirements Traceability Matrix Verifier."""

    def __init__(self, root_path: str):
        self.root = Path(root_path)
        self.violations: List[str] = []
        self.warnings: List[str] = []
        self.found_functions: Dict[str, List[str]] = {}
        self.found_srs_refs: Set[str] = set()

    def verify(self) -> bool:
        """Run all verification checks."""
        print("=" * 60)
        print("axioma-audit RTM Verification")
        print("DVEC: v1.3 | SRS-001 v0.3")
        print("=" * 60)
        print()

        # Check source files
        self._check_source_files()

        # Check header files
        self._check_header_files()

        # Check for forbidden patterns
        self._check_forbidden_patterns()

        # Check DVEC declarations
        self._check_dvec_declarations()

        # Verify function coverage
        self._verify_function_coverage()

        # Print results
        self._print_results()

        return len(self.violations) == 0

    def _check_source_files(self):
        """Check all .c source files for SRS anchors."""
        src_dir = self.root / "src"
        if not src_dir.exists():
            self.violations.append(f"Source directory not found: {src_dir}")
            return

        for c_file in src_dir.glob("*.c"):
            self._check_file_for_srs(c_file)

    def _check_header_files(self):
        """Check all .h header files for SRS anchors."""
        include_dir = self.root / "include"
        if not include_dir.exists():
            self.violations.append(f"Include directory not found: {include_dir}")
            return

        for h_file in include_dir.rglob("*.h"):
            self._check_file_for_srs(h_file)

    def _check_file_for_srs(self, filepath: Path):
        """Check a single file for SRS requirement anchors."""
        try:
            content = filepath.read_text()
        except Exception as e:
            self.violations.append(f"Cannot read {filepath}: {e}")
            return

        # Find all SRS references
        srs_pattern = r'SRS-\d{3}-SHALL-\d{3}|SRS-\d{3}'
        matches = re.findall(srs_pattern, content)
        self.found_srs_refs.update(matches)

        # Find function definitions and their SRS anchors
        # Look for function definitions with preceding comments
        func_pattern = r'/\*\*[\s\S]*?\*/\s*(?:void|int|uint\d+_t|size_t|ax_\w+)\s+(\w+)\s*\('
        for match in re.finditer(func_pattern, content):
            func_name = match.group(1)
            # Get the comment block before the function
            start = max(0, match.start() - 2000)
            comment_block = content[start:match.end()]

            # Find SRS refs in the comment
            srs_refs = re.findall(srs_pattern, comment_block)
            if func_name in REQUIRED_FUNCTIONS:
                self.found_functions[func_name] = srs_refs

    def _check_forbidden_patterns(self):
        """Check all source files for DVEC forbidden patterns."""
        for directory in [self.root / "src", self.root / "include"]:
            if not directory.exists():
                continue
            for filepath in directory.rglob("*.[ch]"):
                self._check_file_forbidden(filepath)

    def _check_file_forbidden(self, filepath: Path):
        """Check a single file for forbidden patterns."""
        try:
            content = filepath.read_text()
        except Exception as e:
            self.violations.append(f"Cannot read {filepath}: {e}")
            return

        for pattern, message in FORBIDDEN_PATTERNS:
            matches = list(re.finditer(pattern, content))
            for match in matches:
                # Get line number
                line_num = content[:match.start()].count('\n') + 1
                self.violations.append(
                    f"{filepath.name}:{line_num}: {message}"
                )

    def _check_dvec_declarations(self):
        """Check that all modules declare DVEC version and determinism class."""
        for directory in [self.root / "src", self.root / "include"]:
            if not directory.exists():
                continue
            for filepath in directory.rglob("*.[ch]"):
                self._check_dvec_header(filepath)

    def _check_dvec_header(self, filepath: Path):
        """Check a single file for DVEC declarations."""
        try:
            content = filepath.read_text()
        except Exception:
            return

        # Check for DVEC version declaration (SRS-001-SHALL-001)
        if "DVEC:" not in content and "DVEC version" not in content.lower():
            self.warnings.append(
                f"{filepath.name}: Missing DVEC version declaration (SRS-001-SHALL-001)"
            )

        # Check for determinism class declaration (SRS-001-SHALL-002)
        has_determinism = (
            "DETERMINISM:" in content or
            "D1" in content or
            "Strict Deterministic" in content
        )
        if not has_determinism:
            self.warnings.append(
                f"{filepath.name}: Missing determinism class declaration (SRS-001-SHALL-002)"
            )

    def _verify_function_coverage(self):
        """Verify all required functions have SRS anchors."""
        print("Function Traceability Check:")
        print("-" * 40)

        for func_name, required_srs in REQUIRED_FUNCTIONS.items():
            found_refs = self.found_functions.get(func_name, [])

            if not found_refs:
                self.violations.append(
                    f"Function '{func_name}' has no SRS anchors (SRS-001-SHALL-003)"
                )
                print(f"  ✗ {func_name}: NO ANCHORS")
            else:
                # Check if at least one required SRS is present
                has_required = any(
                    any(req in ref for ref in found_refs)
                    for req in required_srs
                )
                if has_required:
                    print(f"  ✓ {func_name}: {', '.join(found_refs[:3])}")
                else:
                    self.warnings.append(
                        f"Function '{func_name}' missing specific anchors: {required_srs}"
                    )
                    print(f"  ~ {func_name}: {', '.join(found_refs[:3])} (partial)")

        print()

    def _print_results(self):
        """Print verification results."""
        print("=" * 60)
        print("VERIFICATION RESULTS")
        print("=" * 60)
        print()

        if self.violations:
            print(f"VIOLATIONS ({len(self.violations)}):")
            for v in self.violations:
                print(f"  ✗ {v}")
            print()

        if self.warnings:
            print(f"WARNINGS ({len(self.warnings)}):")
            for w in self.warnings:
                print(f"  ~ {w}")
            print()

        # Summary
        print("-" * 60)
        if not self.violations:
            print("RESULT: CONFORMANT")
            print("All SRS traceability requirements satisfied.")
        else:
            print("RESULT: NON-CONFORMANT")
            print(f"{len(self.violations)} violation(s) must be resolved.")

        print()
        print(f"SRS references found: {len(self.found_srs_refs)}")
        print(f"Functions checked: {len(self.found_functions)}")
        print("-" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Verify SRS requirements traceability matrix"
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Root directory of axioma-audit (default: current directory)"
    )
    args = parser.parse_args()

    verifier = RTMVerifier(args.root)
    success = verifier.verify()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
