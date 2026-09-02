"""
WEIGHTTRAP — Master Test Runner & Quality Assurance Suite
Executes:
1. Core Module Unit Tests (10 test cases)
2. Attack Resilience & Invariance Tests
3. Post-Deployment Tripwire Live Alert Tests
4. REST API Endpoint Tests
5. 40-Model Held-out Benchmark Verification
"""

import os
import sys
import unittest
import time

# Ensure project root in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


def run_master_test_suite():
    print("\n" + "=" * 75)
    print(" WEIGHTTRAP -- 6-ENGINE CONTROL PLANE AUTOMATED TEST SUITE")
    print("=" * 75)

    # 1. Run Unit & Integration Tests across all 6 engines
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir="tests", pattern="test_*.py")
    print(f"\n[+] Running Comprehensive QA Suite ({suite.countTestCases()} Tests across 6 Control Plane Engines)...")
    
    runner = unittest.TextTestRunner(verbosity=2)
    start_time = time.time()
    result = runner.run(suite)
    elapsed = time.time() - start_time

    # 2. Summary
    print("\n" + "=" * 75)
    print(" TEST EXECUTION SUMMARY")
    print("=" * 75)
    print(f" Total Tests Run : {result.testsRun}")
    print(f" Failures        : {len(result.failures)}")
    print(f" Errors          : {len(result.errors)}")
    print(f" Elapsed Time    : {elapsed:.2f} seconds")
    
    if result.wasSuccessful():
        print(f"\n [OK] ALL {result.testsRun} TESTS ACROSS 6 CONTROL PLANE ENGINES PASSED 100%!")
        print("=" * 75)
        return 0
    else:
        print("\n [FAIL] SOME TESTS FAILED. PLEASE CHECK TRACEBACK ABOVE.")
        print("=" * 75)
        return 1


if __name__ == "__main__":
    exit_code = run_master_test_suite()
    sys.exit(exit_code)
