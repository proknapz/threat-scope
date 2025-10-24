#!/usr/bin/env python3
"""
Test script for the mitigation API endpoint
"""

import requests
import json
import os

def test_mitigation_api():
    """Test the mitigation API with our test file"""
    
    print("🧪 Testing Mitigation API...")
    
    # Test file path
    test_file = "test_samples/sql_injection_test.php"
    
    if not os.path.exists(test_file):
        print("❌ Test file not found:", test_file)
        return False
    
    try:
        # Test the mitigation API endpoint
        url = "http://localhost:5000/api/mitigate"
        
        with open(test_file, 'rb') as f:
            files = {'file': (os.path.basename(test_file), f, 'application/x-php')}
            
            print(f"📤 Uploading {test_file} to mitigation API...")
            response = requests.post(url, files=files)
            
        if response.status_code == 200:
            data = response.json()
            
            if data.get('success'):
                print("✅ Mitigation API is working!")
                print(f"📊 Results:")
                print(f"   • Filename: {data['filename']}")
                print(f"   • Total scan results: {data['scan_results']}")
                print(f"   • Vulnerabilities found: {data['vulnerabilities_found']}")
                print(f"   • Fixes generated: {data['fixes_generated']}")
                
                # Show a sample fix
                if data['report']['fixes']:
                    fix = data['report']['fixes'][0]
                    print(f"\n🔧 Sample Fix:")
                    print(f"   • Type: {fix['type']}")
                    print(f"   • Line: {fix['line']}")
                    print(f"   • Vulnerable: {fix['original'][:60]}...")
                    print(f"   • Explanation: {fix['explanation']}")
                
                return True
            else:
                print("❌ Mitigation API returned error:", data.get('error'))
                return False
        else:
            print(f"❌ HTTP Error {response.status_code}: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing mitigation API: {e}")
        return False

def main():
    """Main test function"""
    print("🚀 Testing Threat-Scope Mitigation Features\n")
    
    # Test mitigation API
    mitigation_success = test_mitigation_api()
    
    print(f"\n📊 Test Results:")
    print(f"   • Mitigation API: {'✅ PASS' if mitigation_success else '❌ FAIL'}")
    
    if mitigation_success:
        print("\n🎉 All mitigation tests passed!")
        print("\n💡 You can now:")
        print("   1. Upload PHP files to get vulnerability scans")
        print("   2. Click 'Generate Fixes' button in scan history")
        print("   3. View detailed mitigation suggestions")
        print("   4. Copy fix reports to clipboard")
        
        return True
    else:
        print("\n❌ Some tests failed. Check the error messages above.")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
