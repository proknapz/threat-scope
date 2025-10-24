#!/usr/bin/env python3
"""
Test script to verify the threat-scope setup
"""

import os
import sys
import requests
import time
import subprocess

def test_docker_services():
    """Test if Docker services are running"""
    print("🐳 Testing Docker services...")
    
    try:
        # Check if containers are running
        result = subprocess.run(['docker-compose', 'ps'], capture_output=True, text=True)
        if 'web' in result.stdout and 'mysql' in result.stdout:
            print("✅ Docker services are running")
            return True
        else:
            print("❌ Docker services not running")
            return False
    except Exception as e:
        print(f"❌ Error checking Docker services: {e}")
        return False

def test_web_interface():
    """Test if web interface is accessible"""
    print("🌐 Testing web interface...")
    
    try:
        response = requests.get('http://localhost:5000', timeout=10)
        if response.status_code == 200:
            print("✅ Web interface is accessible")
            return True
        else:
            print(f"❌ Web interface returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error accessing web interface: {e}")
        return False

def test_database_interface():
    """Test if database interface is accessible"""
    print("🗄️ Testing database interface...")
    
    try:
        response = requests.get('http://localhost:5000/database', timeout=10)
        if response.status_code == 200:
            print("✅ Database interface is accessible")
            return True
        else:
            print(f"❌ Database interface returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error accessing database interface: {e}")
        return False

def test_phpmyadmin():
    """Test if phpMyAdmin is accessible"""
    print("🔧 Testing phpMyAdmin...")
    
    try:
        response = requests.get('http://localhost:8080', timeout=10)
        if response.status_code == 200:
            print("✅ phpMyAdmin is accessible")
            return True
        else:
            print(f"❌ phpMyAdmin returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error accessing phpMyAdmin: {e}")
        return False

def test_api_endpoints():
    """Test API endpoints"""
    print("🔌 Testing API endpoints...")
    
    endpoints = [
        '/api/stats',
        '/api/scans',
    ]
    
    success = True
    for endpoint in endpoints:
        try:
            response = requests.get(f'http://localhost:5000{endpoint}', timeout=10)
            if response.status_code == 200:
                print(f"✅ {endpoint} is working")
            else:
                print(f"❌ {endpoint} returned status {response.status_code}")
                success = False
        except Exception as e:
            print(f"❌ Error accessing {endpoint}: {e}")
            success = False
    
    return success

def main():
    """Run all tests"""
    print("🧪 Starting Threat-Scope Setup Tests\n")
    
    tests = [
        test_docker_services,
        test_web_interface,
        test_database_interface,
        test_phpmyadmin,
        test_api_endpoints
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()  # Add spacing between tests
    
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Your Threat-Scope setup is working correctly.")
        print("\n📋 Access URLs:")
        print("  • Main Scanner: http://localhost:5000")
        print("  • Database Management: http://localhost:5000/database")
        print("  • phpMyAdmin: http://localhost:8080")
        return True
    else:
        print("❌ Some tests failed. Please check the setup.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
