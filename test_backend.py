#!/usr/bin/env python3
"""
Simple test script to verify backend functionality
"""

import requests
import json
import time
import os

BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
API_KEY = os.getenv("API_KEY", "dev-admin-key-change-in-production")

def test_health():
    """Test basic health endpoint"""
    print("Testing health endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/health")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_root():
    """Test root endpoint"""
    print("\nTesting root endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/")
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_scanner_health():
    """Test scanner service health"""
    print("\nTesting scanner health endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/api/v1/cenexo-scanner/health")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_scan_with_auth():
    """Test scan endpoint with authentication"""
    print("\nTesting scan endpoint with authentication...")
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
    }

    scan_data = {
        "targets": ["127.0.0.1"],
        "scan_type": "basic",
        "ports": "22,80,443,8000",
        "timeout": 30
    }

    try:
        response = requests.post(
            f"{BASE_URL}/api/v1/cenexo-scanner/scan",
            headers=headers,
            json=scan_data
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    """Run all tests"""
    print("=== Cenexo Backend Test Suite ===")
    print(f"Testing against: {BASE_URL}")
    print(f"Using API Key: {API_KEY[:10]}...")

    tests = [
        ("Health Check", test_health),
        ("Root Endpoint", test_root),
        ("Scanner Health", test_scanner_health),
        ("Scan with Auth", test_scan_with_auth)
    ]

    results = []
    for test_name, test_func in tests:
        print(f"\n{'='*50}")
        print(f"Running: {test_name}")
        print('='*50)
        result = test_func()
        results.append((test_name, result))
        time.sleep(1)  # Brief pause between tests

    print(f"\n{'='*50}")
    print("TEST SUMMARY")
    print('='*50)
    passed = 0
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"{test_name}: {status}")
        if result:
            passed += 1

    print(f"\nResults: {passed}/{len(results)} tests passed")

    if passed == len(results):
        print("🎉 All tests passed! Backend is working correctly.")
    else:
        print("❌ Some tests failed. Check the output above for details.")

if __name__ == "__main__":
    main()