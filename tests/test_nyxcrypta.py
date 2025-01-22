import pytest
import os
import tempfile
from nyxcrypta.core.crypto import NyxCrypta
from nyxcrypta.core.security import SecurityLevel

class TestNyxCrypta:
    @pytest.fixture
    def nyxcrypta(self):
        return NyxCrypta(SecurityLevel.STANDARD)
    
    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdirname:
            yield tmpdirname
    
    def test_key_generation(self, nyxcrypta, temp_dir):
        # Test key pair generation
        password = "test_password123"
        assert nyxcrypta.save_keys(temp_dir, password) == True
        
        # Verify files were created
        private_key_path = os.path.join(temp_dir, 'private_key.pem')
        public_key_path = os.path.join(temp_dir, 'public_key.pem')
        assert os.path.exists(private_key_path)
        assert os.path.exists(public_key_path)
    
    def test_file_encryption_decryption(self, nyxcrypta, temp_dir):
        # Create test file
        test_data = b"Hello, World!"
        input_file = os.path.join(temp_dir, 'test.txt')
        with open(input_file, 'wb') as f:
            f.write(test_data)
        
        # Generate keys
        password = "test_password123"
        nyxcrypta.save_keys(temp_dir, password)
        
        # Test encryption
        encrypted_file = os.path.join(temp_dir, 'test.encrypted')
        assert nyxcrypta.encrypt_file(
            input_file,
            encrypted_file,
            os.path.join(temp_dir, 'public_key.pem')
        ) == True
        
        # Test decryption
        decrypted_file = os.path.join(temp_dir, 'test.decrypted')
        assert nyxcrypta.decrypt_file(
            encrypted_file,
            decrypted_file,
            os.path.join(temp_dir, 'private_key.pem'),
            password
        ) == True
        
        # Verify decrypted content matches original
        with open(decrypted_file, 'rb') as f:
            decrypted_data = f.read()
        assert decrypted_data == test_data
    
    def test_data_encryption_decryption(self, nyxcrypta, temp_dir):
        # Generate keys
        password = "test_password123"
        nyxcrypta.save_keys(temp_dir, password)
        
        # Test data encryption/decryption
        test_data = b"Secret message"
        
        # Encrypt data
        encrypted_data = nyxcrypta.encrypt_data(
            test_data,
            os.path.join(temp_dir, 'public_key.pem')
        )
        assert encrypted_data is not None
        
        # Decrypt data
        decrypted_data = nyxcrypta.decrypt_data(
            bytes.fromhex(encrypted_data),
            os.path.join(temp_dir, 'private_key.pem'),
            password
        )
        assert decrypted_data == test_data
    
    def test_security_levels(self, temp_dir):
        password = "test_password123"
        
        # Test each security level
        for level in SecurityLevel:
            nx = NyxCrypta(level)
            assert nx.save_keys(temp_dir, password) == True