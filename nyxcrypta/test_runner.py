import os
import sys
import tempfile
import struct
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nyxcrypta.core.crypto import NyxCrypta
from nyxcrypta.core.security import SecurityLevel
from nyxcrypta.core.compatibility import KeyConverter, KeyFormat
import logging

class TestRunner:
    def __init__(self):
        self.failed_tests = []
        self.passed_tests = []
        self.setup_logging()
        
        # Define all tests to run
        self.tests = [
            self.test_key_generation,
            self.test_file_encryption_decryption,
            self.test_data_encryption_decryption,
            self.test_security_levels,
            self.test_key_format_conversion,
            self.test_large_file_roundtrip,
            self.test_unique_nonce_per_chunk,
            self.test_tamper_reorder_truncate_detected,
            self.test_empty_file_and_wrong_password,
            self.test_legacy_v2_decryption,
            self.test_data_header_authenticated,
            self.test_json_private_key_is_encrypted,
            self.test_ssh_keygen_keeps_private_key
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
        
        # Test key generation for each format
        for key_format in [KeyFormat.PEM, KeyFormat.DER]:
            assert nx.save_keys(temp_dir, password, key_format) == True, f"Key generation failed for {key_format} format"
            
            # Verify files were created with correct extension
            ext = key_format.lower()
            private_key_path = os.path.join(temp_dir, f'private_key.{ext}')
            public_key_path = os.path.join(temp_dir, f'public_key.{ext}')
            assert os.path.exists(private_key_path), f"Private key file not created for {key_format} format"
            assert os.path.exists(public_key_path), f"Public key file not created for {key_format} format"

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
        nx.save_keys(temp_dir, password, KeyFormat.PEM)
        
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
        nx.save_keys(temp_dir, password, KeyFormat.PEM)
        
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
            assert nx.save_keys(temp_dir, password, KeyFormat.PEM) == True, f"Key generation failed for security level {level.name}"

    def test_key_format_conversion(self, temp_dir):
        """Test key format conversion"""
        nx = NyxCrypta(SecurityLevel.STANDARD)
        password = "test_password123"
        
        # Generate initial keys in PEM format
        nx.save_keys(temp_dir, password, KeyFormat.PEM)
        
        # Test public key conversions
        formats = [KeyFormat.PEM, KeyFormat.DER, KeyFormat.SSH]  # Remove JSON from initial formats
        for from_format in formats:
            # Generate key in the source format
            nx.save_keys(temp_dir, password, from_format)
            
            # Get the source key file
            source_key_path = os.path.join(temp_dir, f'public_key.{from_format.lower()}')
            with open(source_key_path, 'rb') as f:
                key_data = f.read()
            
            # Test conversion to each target format
            target_formats = formats + [KeyFormat.JSON]  # Add JSON as target format only
            for to_format in target_formats:
                if from_format == to_format:
                    continue
                
                try:
                    # Convert to target format
                    converted_key = KeyConverter.convert_public_key(
                        key_data,
                        from_format,  # Use actual source format
                        to_format
                    )
                    assert converted_key is not None, f"Public key conversion failed from {from_format} to {to_format}"
                    
                    # Skip conversion back for JSON format
                    if to_format != KeyFormat.JSON:
                        # Test conversion back
                        back_converted = KeyConverter.convert_public_key(
                            converted_key,
                            to_format,
                            from_format
                        )
                        assert back_converted is not None, f"Public key conversion failed from {to_format} back to {from_format}"
                except Exception as e:
                    raise AssertionError(f"Public key conversion error: {from_format} to {to_format} - {str(e)}")
        
        # Test private key conversions
        private_formats = [KeyFormat.PEM, KeyFormat.DER]  # Remove JSON from initial formats
        for from_format in private_formats:
            # Generate key in the source format
            nx.save_keys(temp_dir, password, from_format)
            
            # Get the source key file
            source_key_path = os.path.join(temp_dir, f'private_key.{from_format.lower()}')
            with open(source_key_path, 'rb') as f:
                key_data = f.read()
            
            # Test conversion to each target format
            target_formats = private_formats + [KeyFormat.JSON]  # Add JSON as target format only
            for to_format in target_formats:
                if from_format == to_format:
                    continue
                
                try:
                    # Convert to target format
                    converted_key = KeyConverter.convert_private_key(
                        key_data,
                        from_format,  # Use actual source format
                        to_format,
                        password.encode()
                    )
                    assert converted_key is not None, f"Private key conversion failed from {from_format} to {to_format}"
                    
                    # Skip conversion back for JSON format
                    if to_format != KeyFormat.JSON:
                        # Test conversion back
                        back_converted = KeyConverter.convert_private_key(
                            converted_key,
                            to_format,
                            from_format,
                            password.encode()
                        )
                        assert back_converted is not None, f"Private key conversion failed from {to_format} back to {from_format}"
                except Exception as e:
                    raise AssertionError(f"Private key conversion error: {from_format} to {to_format} - {str(e)}")

    # ---- regression tests for the v3 container format -----------------------

    def _setup_keys(self, temp_dir, password="test_password123"):
        nx = NyxCrypta(SecurityLevel.STANDARD)
        assert nx.save_keys(temp_dir, password, KeyFormat.PEM), "Key generation failed"
        return nx, os.path.join(temp_dir, 'public_key.pem'), os.path.join(temp_dir, 'private_key.pem')

    def _encrypt_small_chunks(self, nx, temp_dir, plaintext, pub, chunk_size=1024):
        nx.chunk_size = chunk_size
        src = os.path.join(temp_dir, 'src.bin')
        enc = os.path.join(temp_dir, 'src.nyx')
        with open(src, 'wb') as f:
            f.write(plaintext)
        assert nx.encrypt_file(src, enc, pub), "File encryption failed"
        return enc

    def test_large_file_roundtrip(self, temp_dir):
        """Files larger than one chunk must round-trip (default 1MB chunks)"""
        nx, pub, priv = self._setup_keys(temp_dir)
        data = os.urandom(2 * 1024 * 1024 + 5)
        src = os.path.join(temp_dir, 'big.bin')
        with open(src, 'wb') as f:
            f.write(data)
        enc, out = src + '.nyx', src + '.out'
        assert nx.encrypt_file(src, enc, pub), "Encryption of a multi-chunk file failed"
        assert nx.decrypt_file(enc, out, priv, "test_password123"), "Decryption of a multi-chunk file failed"
        with open(out, 'rb') as f:
            assert f.read() == data, "Multi-chunk round-trip mismatch"
        # exact multiple of the chunk size
        nx.chunk_size = 1024
        data = os.urandom(4096)
        enc = self._encrypt_small_chunks(nx, temp_dir, data, pub)
        assert nx.decrypt_file(enc, out, priv, "test_password123"), "Exact-multiple file failed"
        with open(out, 'rb') as f:
            assert f.read() == data, "Exact-multiple round-trip mismatch"

    def test_unique_nonce_per_chunk(self, temp_dir):
        """Identical plaintext chunks must not produce identical ciphertext blocks"""
        nx, pub, priv = self._setup_keys(temp_dir)
        enc = self._encrypt_small_chunks(nx, temp_dir, b'A' * 1024 * 4, pub)
        with open(enc, 'rb') as f:
            blob = f.read()
        header_len = 1 + 4 + struct.unpack('<I', blob[1:5])[0] + 8 + 4
        body = blob[header_len:]
        block = 1024 + 16
        blocks = [body[i:i + block] for i in range(0, len(body), block)]
        assert len(blocks) == 4, f"Expected 4 blocks, got {len(blocks)}"
        assert len(set(blocks)) == 4, "Nonce reuse: identical chunks gave identical ciphertext"

    def test_tamper_reorder_truncate_detected(self, temp_dir):
        """Any modification of the ciphertext or header must be rejected"""
        nx, pub, priv = self._setup_keys(temp_dir)
        enc = self._encrypt_small_chunks(nx, temp_dir, os.urandom(4096), pub)
        with open(enc, 'rb') as f:
            blob = f.read()
        out = os.path.join(temp_dir, 'out.bin')
        header_len = 1 + 4 + struct.unpack('<I', blob[1:5])[0] + 8 + 4
        block = 1024 + 16

        def rejected(modified, label):
            path = os.path.join(temp_dir, 'mod.nyx')
            with open(path, 'wb') as f:
                f.write(modified)
            assert nx.decrypt_file(path, out, priv, "test_password123") is False, f"{label} was not detected"
            assert not os.path.exists(out), f"Partial output left behind after {label}"
            assert not os.path.exists(out + '.part'), f"Temp file left behind after {label}"

        flipped = bytearray(blob); flipped[header_len + 10] ^= 1
        rejected(bytes(flipped), "bit flip in ciphertext")
        rejected(blob[:header_len + 2 * block], "truncation at a chunk boundary")
        rejected(blob[:-1], "truncation of the last byte")
        b = [blob[header_len + i * block: header_len + (i + 1) * block] for i in range(4)]
        rejected(blob[:header_len] + b[1] + b[0] + b[2] + b[3], "chunk reordering")
        rejected(blob[:header_len] + b[0] + b[0] + b[2] + b[3], "chunk duplication")
        chunk_size_offset = header_len - 4
        hdr = bytearray(blob); hdr[chunk_size_offset] ^= 0x01
        rejected(bytes(hdr), "header (chunk size) modification")

    def test_empty_file_and_wrong_password(self, temp_dir):
        """Empty files round-trip; a wrong password fails cleanly"""
        nx, pub, priv = self._setup_keys(temp_dir)
        src, enc, out = (os.path.join(temp_dir, n) for n in ('e', 'e.nyx', 'e.out'))
        open(src, 'wb').close()
        assert nx.encrypt_file(src, enc, pub), "Empty file encryption failed"
        assert nx.decrypt_file(enc, out, priv, "test_password123"), "Empty file decryption failed"
        assert os.path.getsize(out) == 0, "Empty file round-trip mismatch"
        assert nx.decrypt_file(enc, out + '2', priv, "wrong") is False, "Wrong password accepted"

    def test_legacy_v2_decryption(self, temp_dir):
        """Files written by the old (v2) format must still be readable, including > 1 chunk"""
        nx, pub, priv = self._setup_keys(temp_dir)
        public_key = serialization.load_pem_public_key(open(pub, 'rb').read())
        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        wrapped = public_key.encrypt(aes_key, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        plaintext = os.urandom(2500)
        cs = 1024
        legacy = struct.pack('<B', 2) + struct.pack('<I', len(wrapped)) + wrapped + nonce
        for i in range(0, len(plaintext), cs):
            legacy += AESGCM(aes_key).encrypt(nonce, plaintext[i:i + cs], None)
        src, out = os.path.join(temp_dir, 'legacy.nyx'), os.path.join(temp_dir, 'legacy.out')
        with open(src, 'wb') as f:
            f.write(legacy)
        nx.chunk_size = cs
        assert nx.decrypt_file(src, out, priv, "test_password123"), "Legacy v2 decryption failed"
        with open(out, 'rb') as f:
            assert f.read() == plaintext, "Legacy v2 round-trip mismatch"

    def test_data_header_authenticated(self, temp_dir):
        """Modifying the data-mode header must be detected"""
        nx, pub, priv = self._setup_keys(temp_dir)
        enc = bytearray(bytes.fromhex(nx.encrypt_data(b"secret", pub)))
        assert nx.decrypt_data(bytes(enc), priv, "test_password123") == b"secret", "Data round-trip failed"
        enc[10] ^= 1  # inside the wrapped key
        assert nx.decrypt_data(bytes(enc), priv, "test_password123") is None, "Tampered data accepted"

    def test_json_private_key_is_encrypted(self, temp_dir):
        """JSON export must never contain an unencrypted private key"""
        nx, pub, priv = self._setup_keys(temp_dir)
        pem = open(priv, 'rb').read()
        password = b"test_password123"
        as_json = KeyConverter.convert_private_key(pem, KeyFormat.PEM, KeyFormat.JSON, password)
        inner = base64.b64decode(json.loads(as_json)["key"])
        assert b"ENCRYPTED PRIVATE KEY" in inner, "JSON private key is not encrypted"
        clear_pem = serialization.load_pem_private_key(pem, password).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        try:
            KeyConverter.convert_private_key(clear_pem, KeyFormat.PEM, KeyFormat.JSON, None)
            raise AssertionError("JSON export without password was accepted")
        except ValueError as e:
            assert "password is required" in str(e), f"Unexpected error: {e}"
        back = KeyConverter.convert_private_key(as_json, KeyFormat.JSON, KeyFormat.PEM, password)
        assert b"ENCRYPTED PRIVATE KEY" in back, "JSON -> PEM lost the encryption"

    def test_ssh_keygen_keeps_private_key(self, temp_dir):
        """keygen -f SSH must keep the private key and the result must be usable"""
        nx = NyxCrypta(SecurityLevel.STANDARD)
        assert nx.save_keys(temp_dir, "test_password123", KeyFormat.SSH), "SSH key generation failed"
        priv = os.path.join(temp_dir, 'private_key.pem')
        pub = os.path.join(temp_dir, 'public_key.ssh')
        assert os.path.exists(priv), "Private key was not saved for SSH format"
        assert os.path.exists(pub), "SSH public key missing"
        enc = nx.encrypt_data(b"via ssh key", pub)
        assert nx.decrypt_data(bytes.fromhex(enc), priv, "test_password123") == b"via ssh key", \
            "SSH public key / PEM private key round-trip failed"

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