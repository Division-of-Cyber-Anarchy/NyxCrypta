import os
import sys
import tempfile
from nyxcrypta.core.crypto import NyxCrypta
from nyxcrypta.core.security import SecurityLevel
import logging

class TestRunner:
    def __init__(self):
        self.failed_tests = []
        self.passed_tests = []
        self.setup_logging()
        
        # Exécuter tous les tests définis
        self.tests = [
            self.test_key_generation,
            self.test_file_encryption_decryption,
            self.test_data_encryption_decryption,
            self.test_security_levels
        ]

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def run_test(self, test_func):
        """Run a single test with proper setup and teardown"""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                test_func(temp_dir)
            self.passed_tests.append(test_func.__name__)
            return True
        except AssertionError as e:
            self.failed_tests.append((test_func.__name__, str(e)))
            return False
        except Exception as e:
            self.failed_tests.append((test_func.__name__, f"Unexpected error: {str(e)}"))
            return False

    def run_all_tests(self):
        """Run all tests"""
        print("\n🚀 Starting NyxCrypta tests...\n")
        total_tests = len(self.tests)
        passed = 0

        for test in self.tests:
            print(f"Running test: {test.__name__}...")
            if self.run_test(test):
                passed += 1
                print(f"✅ {test.__name__} passed\n")
            else:
                print(f"❌ {test.__name__} failed\n")

        return {
            'total': total_tests,
            'passed': passed,
            'failed': total_tests - passed,
            'failed_tests': self.failed_tests
        }

    def test_key_generation(self, temp_dir):
        """Test key pair generation"""
        nx = NyxCrypta(SecurityLevel.STANDARD)
        password = "test_password123"
        
        # Test key generation
        assert nx.save_keys(temp_dir, password) == True, "Key generation failed"
        
        # Verify files were created
        private_key_path = os.path.join(temp_dir, 'private_key.pem')
        public_key_path = os.path.join(temp_dir, 'public_key.pem')
        assert os.path.exists(private_key_path), "Private key file not created"
        assert os.path.exists(public_key_path), "Public key file not created"

    def test_file_encryption_decryption(self, temp_dir):
        """Test file encryption and decryption"""
        nx = NyxCrypta(SecurityLevel.STANDARD)
        password = "test_password123"
        
        # Create test file
        test_data = b"Hello, World!"
        input_file = os.path.join(temp_dir, 'test.txt')
        with open(input_file, 'wb') as f:
            f.write(test_data)
        
        # Generate keys
        nx.save_keys(temp_dir, password)
        
        # Test encryption
        encrypted_file = os.path.join(temp_dir, 'test.encrypted')
        assert nx.encrypt_file(
            input_file,
            encrypted_file,
            os.path.join(temp_dir, 'public_key.pem')
        ) == True, "File encryption failed"
        
        # Test decryption
        decrypted_file = os.path.join(temp_dir, 'test.decrypted')
        assert nx.decrypt_file(
            encrypted_file,
            decrypted_file,
            os.path.join(temp_dir, 'private_key.pem'),
            password
        ) == True, "File decryption failed"
        
        # Verify decrypted content matches original
        with open(decrypted_file, 'rb') as f:
            decrypted_data = f.read()
        assert decrypted_data == test_data, "Decrypted data does not match original"

    def test_data_encryption_decryption(self, temp_dir):
        """Test raw data encryption and decryption"""
        nx = NyxCrypta(SecurityLevel.STANDARD)
        password = "test_password123"
        
        # Generate keys
        nx.save_keys(temp_dir, password)
        
        # Test data
        test_data = b"Secret message"
        
        # Encrypt data
        encrypted_data = nx.encrypt_data(
            test_data,
            os.path.join(temp_dir, 'public_key.pem')
        )
        assert encrypted_data is not None, "Data encryption failed"
        
        # Decrypt data
        decrypted_data = nx.decrypt_data(
            bytes.fromhex(encrypted_data),
            os.path.join(temp_dir, 'private_key.pem'),
            password
        )
        assert decrypted_data == test_data, "Decrypted data does not match original"

    def test_security_levels(self, temp_dir):
        """Test different security levels"""
        password = "test_password123"
        
        for level in SecurityLevel:
            nx = NyxCrypta(level)
            assert nx.save_keys(temp_dir, password) == True, f"Key generation failed for security level {level.name}"

def main():
    """Main entry point for the test runner"""
    try:
        runner = TestRunner()
        results = runner.run_all_tests()
        
        # Print summary
        print("\n📊 Test Summary:")
        print(f"Total tests: {results['total']}")
        print(f"Passed: {results['passed']}")
        print(f"Failed: {results['failed']}")
        
        if results['failed_tests']:
            print("\n❌ Failed Tests:")
            for test_name, error in results['failed_tests']:
                print(f"- {test_name}: {error}")
            sys.exit(1)
        else:
            print("\n✨ All tests passed successfully!")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n⚠️ Test execution interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n💥 Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()