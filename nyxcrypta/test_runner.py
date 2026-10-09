import os
import sys
import tempfile
import shutil
import struct
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nyxcrypta.core.crypto import NyxCrypta
from nyxcrypta.core.security import SecurityLevel
from nyxcrypta.core.compatibility import KeyConverter, KeyFormat, load_private_key
from nyxcrypta.core import security
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
            self.test_ssh_keygen_keeps_private_key,
            self.test_der_keys_and_explicit_key_format,
            self.test_keygen_json_roundtrip,
            self.test_failed_encryption_leaves_no_output,
            self.test_empty_and_binary_data_cli,
            self.test_convert_detects_key_type_from_content,
            self.test_handle_command_never_exits,
            self.test_argon2_key_container,
            self.test_argon2_rejects_excessive_parameters,
            self.test_legacy_pkcs8_keys_load_and_upgrade,
            self.test_signature_roundtrip_and_tampering,
            self.test_signature_key_type_checks,
            self.test_signature_all_key_formats,
            self.test_sign_data_api,
            self.test_signature_cli
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
        assert b"BEGIN NYXCRYPTA ENCRYPTED PRIVATE KEY" in inner, "JSON private key is not encrypted"
        clear_pem = load_private_key(pem, password).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        try:
            KeyConverter.convert_private_key(clear_pem, KeyFormat.PEM, KeyFormat.JSON, None)
            raise AssertionError("JSON export without password was accepted")
        except ValueError as e:
            assert "password is required" in str(e), f"Unexpected error: {e}"
        back = KeyConverter.convert_private_key(as_json, KeyFormat.JSON, KeyFormat.PEM, password)
        assert b"BEGIN NYXCRYPTA ENCRYPTED PRIVATE KEY" in back, "JSON -> PEM lost the encryption"

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

    # ---- regression tests for 3.1.0 ------------------------------------------

    def test_der_keys_and_explicit_key_format(self, temp_dir):
        """DER keys work (auto-detected); an explicit --key-format is honoured"""
        nx = NyxCrypta(SecurityLevel.STANDARD)
        assert nx.save_keys(temp_dir, "test_password123", KeyFormat.DER), "DER key generation failed"
        pub = os.path.join(temp_dir, 'public_key.der')
        priv = os.path.join(temp_dir, 'private_key.der')
        enc = nx.encrypt_data(b"der data", pub)
        assert enc, "encrypt_data failed with a DER public key"
        assert nx.decrypt_data(bytes.fromhex(enc), priv, "test_password123") == b"der data", "DER round-trip failed"
        assert nx.encrypt_data(b"x", pub, KeyFormat.DER), "Explicit DER format rejected"
        assert nx.encrypt_data(b"x", pub, KeyFormat.PEM) is None, "Explicit PEM accepted a DER key"
        src, out = os.path.join(temp_dir, 'f.bin'), os.path.join(temp_dir, 'f.nyx')
        with open(src, 'wb') as f:
            f.write(b"file data")
        assert nx.encrypt_file(src, out, pub, KeyFormat.DER), "File encryption with DER key failed"
        assert nx.decrypt_file(out, src + '.out', priv, "test_password123", KeyFormat.DER), \
            "File decryption with DER key failed"

    def test_keygen_json_roundtrip(self, temp_dir):
        """keygen -f JSON produces usable keys and the private key is encrypted"""
        nx = NyxCrypta(SecurityLevel.STANDARD)
        assert nx.save_keys(temp_dir, "test_password123", KeyFormat.JSON), "JSON key generation failed"
        pub = os.path.join(temp_dir, 'public_key.json')
        priv = os.path.join(temp_dir, 'private_key.json')
        assert os.path.exists(pub) and os.path.exists(priv), "JSON key files missing"
        inner = base64.b64decode(json.load(open(priv))["key"])
        assert b"BEGIN NYXCRYPTA ENCRYPTED PRIVATE KEY" in inner, "Generated JSON private key is not encrypted"
        enc = nx.encrypt_data(b"json keys", pub)
        assert nx.decrypt_data(bytes.fromhex(enc), priv, "test_password123") == b"json keys", \
            "JSON keys round-trip failed"

    def test_failed_encryption_leaves_no_output(self, temp_dir):
        """A failed encryption must not leave a partial output file"""
        nx, pub, priv = self._setup_keys(temp_dir)
        out = os.path.join(temp_dir, 'never.nyx')
        assert nx.encrypt_file(os.path.join(temp_dir, 'missing.bin'), out, pub) is False, \
            "Encryption of a missing file reported success"
        assert not os.path.exists(out) and not os.path.exists(out + '.part'), "Partial output left behind"

    def _run_cli(self, args):
        """Runs handle_command and returns (result, captured stdout)"""
        import io
        from contextlib import redirect_stdout
        from argparse import Namespace
        from nyxcrypta.cli.commands import handle_command
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            result = handle_command(Namespace(**args), NyxCrypta(SecurityLevel.STANDARD))
        return result, buffer.getvalue()

    def test_empty_and_binary_data_cli(self, temp_dir):
        """decryptdata must accept an empty plaintext and not crash on binary data"""
        nx, pub, priv = self._setup_keys(temp_dir)
        common = dict(command='decryptdata', key=priv, password="test_password123", key_format=None)

        result, _ = self._run_cli(dict(common, data=nx.encrypt_data(b"", pub)))
        assert result is True, "Empty plaintext treated as a failure"

        binary = bytes([0xff, 0xfe, 0x00, 0x80])
        result, output = self._run_cli(dict(common, data=nx.encrypt_data(binary, pub)))
        assert result is True, "Binary plaintext treated as a failure"
        assert binary.hex() in output, "Binary plaintext not displayed as hexadecimal"

    def test_convert_detects_key_type_from_content(self, temp_dir):
        """convert must rely on the key content, not on a 'public' substring in the path"""
        nx, pub, priv = self._setup_keys(temp_dir)
        public_dir = os.path.join(temp_dir, 'public')
        os.makedirs(public_dir)
        private_in_public_dir = os.path.join(public_dir, 'private_key.pem')
        shutil.copy(priv, private_in_public_dir)
        out = os.path.join(temp_dir, 'private_key.der')
        result, _ = self._run_cli(dict(
            command='convert', input=private_in_public_dir, output=out,
            from_format='PEM', to_format='DER', public=False, password="test_password123"))
        assert result is True, "Private key in a 'public' directory was handled as a public key"
        loaded = load_private_key(open(out, 'rb').read(), b"test_password123")
        assert loaded.key_size == 2048, "Converted private key is not usable"

        # a public key whose path does not contain 'public' is detected as public
        renamed = os.path.join(temp_dir, 'my_key.pem')
        shutil.copy(pub, renamed)
        out_pub = os.path.join(temp_dir, 'my_key.der')
        result, _ = self._run_cli(dict(
            command='convert', input=renamed, output=out_pub,
            from_format='PEM', to_format='DER', public=False, password=None))
        assert result is True, "Public key without 'public' in its path was not detected"

    def test_handle_command_never_exits(self, temp_dir):
        """Errors return False instead of terminating the (interactive) session"""
        try:
            result, _ = self._run_cli(dict(
                command='decrypt', input=os.path.join(temp_dir, 'missing.nyx'),
                output=os.path.join(temp_dir, 'o'), key=os.path.join(temp_dir, 'missing.pem'),
                password="x", key_format=None))
        except SystemExit:
            raise AssertionError("handle_command called sys.exit()")
        assert result is False, "A failing command did not return False"
        try:
            result, _ = self._run_cli(dict(command='convert', input=os.path.join(temp_dir, 'nope'),
                                           output='x', from_format='PEM', to_format='DER',
                                           public=False, password=None))
        except SystemExit:
            raise AssertionError("handle_command called sys.exit() on an exception")
        assert result is False, "An exception did not turn into a False result"

    # ---- tests for 3.2.0: Argon2id key protection and Ed25519 signatures ------

    def test_argon2_key_container(self, temp_dir):
        """Private keys use the Argon2id container; its parameters are authenticated"""
        nx, pub, priv = self._setup_keys(temp_dir)
        pem = open(priv, 'rb').read()
        assert pem.startswith(b"-----BEGIN NYXCRYPTA ENCRYPTED PRIVATE KEY-----"), "Private key is not a NyxCrypta container"
        assert b"-----BEGIN ENCRYPTED PRIVATE KEY-----" not in pem, "Private key still uses standard PKCS8 encryption"

        blob = security.dearmor(pem)
        assert blob[:4] == security.MAGIC, "Missing container magic"
        version, kdf, time_cost, memory_cost, parallelism = struct.unpack("<BBIIB", blob[4:15])
        expected = security.ARGON2_PARAMS[SecurityLevel.STANDARD]
        assert kdf == security.KDF_ARGON2ID, "Key derivation is not Argon2id"
        assert (time_cost, memory_cost, parallelism) == (
            expected.time_cost, expected.memory_cost, expected.parallelism), "Unexpected Argon2 parameters"

        levels = [security.ARGON2_PARAMS[l] for l in (SecurityLevel.STANDARD, SecurityLevel.HIGH, SecurityLevel.PARANOID)]
        assert levels[0].memory_cost < levels[1].memory_cost < levels[2].memory_cost, "Argon2 cost does not grow with the level"
        assert all(l.memory_cost <= security.MAX_MEMORY_COST for l in levels), "A level exceeds the accepted bounds"

        # salt and nonce are unique per key, even with the same password
        other_dir = os.path.join(temp_dir, 'other')
        nx.save_keys(other_dir, "test_password123", KeyFormat.PEM)
        other = security.dearmor(open(os.path.join(other_dir, 'private_key.pem'), 'rb').read())
        assert blob[15:43] != other[15:43], "Salt/nonce reused between two keys"

        # DER is the raw binary container
        der_dir = os.path.join(temp_dir, 'der')
        nx.save_keys(der_dir, "test_password123", KeyFormat.DER)
        assert open(os.path.join(der_dir, 'private_key.der'), 'rb').read().startswith(security.MAGIC), \
            "DER private key is not the binary container"

        encrypted = nx.encrypt_data(b"argon2", pub)
        assert nx.decrypt_data(bytes.fromhex(encrypted), priv, "test_password123") == b"argon2", "Round-trip failed"
        assert nx.decrypt_data(bytes.fromhex(encrypted), priv, "wrong") is None, "Wrong password accepted"

        # lowering the Argon2 time cost in the header must be rejected (the parameters
        # feed the key derivation and the whole header is also authenticated as AAD)
        tampered = bytearray(blob)
        tampered[6] ^= 0x01
        tampered_path = os.path.join(temp_dir, 'tampered.pem')
        with open(tampered_path, 'wb') as f:
            f.write(security.armor(bytes(tampered)))
        assert nx.decrypt_data(bytes.fromhex(encrypted), tampered_path, "test_password123") is None, \
            "Tampered Argon2 parameters were accepted"

    def test_argon2_rejects_excessive_parameters(self, temp_dir):
        """A crafted key file cannot force huge memory/time usage; empty passwords are refused"""
        small = security.Argon2Params(time_cost=1, memory_cost=8, parallelism=1)
        payload = b"k" * 48
        blob = security.protect_private_key(payload, b"pw", small)
        assert security.unprotect_private_key(blob, b"pw") == payload, "Container round-trip failed"

        crafted = bytearray(blob)
        crafted[10:14] = struct.pack("<I", 2 ** 30)  # 1 TiB expressed in KiB
        try:
            security.unprotect_private_key(bytes(crafted), b"pw")
            raise AssertionError("Excessive memory cost accepted")
        except ValueError as e:
            assert "memory" in str(e), f"Unexpected error: {e}"

        for bad in (security.Argon2Params(0, 8, 1), security.Argon2Params(1, 8, 0),
                    security.Argon2Params(1, 2 ** 30, 1), security.Argon2Params(10 ** 6, 8, 1)):
            try:
                security.protect_private_key(payload, b"pw", bad)
                raise AssertionError(f"Out-of-bounds parameters accepted: {bad}")
            except ValueError:
                pass
        try:
            security.protect_private_key(payload, b"", small)
            raise AssertionError("Empty password accepted")
        except ValueError:
            pass

    def test_legacy_pkcs8_keys_load_and_upgrade(self, temp_dir):
        """Keys from 3.1.0 and earlier (standard encrypted PKCS8) still work and can be upgraded"""
        nx = NyxCrypta(SecurityLevel.STANDARD)
        private_key, public_key = nx.generate_rsa_keypair()
        password = b"test_password123"
        enc = serialization.BestAvailableEncryption(password)
        legacy_pem = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
        legacy_der = private_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, enc)
        pub = os.path.join(temp_dir, 'pub.pem')
        with open(pub, 'wb') as f:
            f.write(public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        message = nx.encrypt_data(b"legacy", pub)

        for name, data in (('legacy.pem', legacy_pem), ('legacy.der', legacy_der)):
            path = os.path.join(temp_dir, name)
            with open(path, 'wb') as f:
                f.write(data)
            assert nx.decrypt_data(bytes.fromhex(message), path, "test_password123") == b"legacy", \
                f"Legacy {name} key could not be used"

        upgraded = KeyConverter.convert_private_key(legacy_pem, KeyFormat.PEM, KeyFormat.PEM, password)
        assert upgraded.startswith(b"-----BEGIN NYXCRYPTA ENCRYPTED PRIVATE KEY-----"), "Legacy key was not upgraded to Argon2id"
        upgraded_path = os.path.join(temp_dir, 'upgraded.pem')
        with open(upgraded_path, 'wb') as f:
            f.write(upgraded)
        assert nx.decrypt_data(bytes.fromhex(message), upgraded_path, "test_password123") == b"legacy", \
            "Upgraded key cannot decrypt"

    def _signing_setup(self, temp_dir, key_format=KeyFormat.PEM):
        nx = NyxCrypta(SecurityLevel.STANDARD)
        assert nx.save_signing_keys(temp_dir, "test_password123", key_format), "Signing key generation failed"
        private_ext = 'pem' if key_format == KeyFormat.SSH else key_format.lower()
        return (nx,
                os.path.join(temp_dir, f'signing_public_key.{key_format.lower()}'),
                os.path.join(temp_dir, f'signing_private_key.{private_ext}'))

    def test_signature_roundtrip_and_tampering(self, temp_dir):
        """Valid signatures verify; any change to the file, signature or key is rejected"""
        nx, pub, priv = self._signing_setup(temp_dir)
        src = os.path.join(temp_dir, 'doc.bin')
        data = os.urandom(3 * 1024 * 1024 + 7)  # several read chunks
        with open(src, 'wb') as f:
            f.write(data)
        sig = src + '.sig'
        assert nx.sign_file(src, priv, "test_password123"), "Signing failed"
        assert os.path.exists(sig), "Default signature file was not created"
        assert nx.verify_file(src, sig, pub) is True, "Valid signature rejected"

        def verify_variant(content, label):
            path = os.path.join(temp_dir, 'variant.bin')
            with open(path, 'wb') as f:
                f.write(content)
            assert nx.verify_file(path, sig, pub) is False, f"{label} was not detected"

        flipped = bytearray(data); flipped[1_500_000] ^= 1
        verify_variant(bytes(flipped), "bit flip in the file")
        verify_variant(data[:-1], "truncated file")
        verify_variant(data + b"\x00", "appended byte")

        doc = json.load(open(sig))
        raw = bytearray(base64.b64decode(doc["signature"])); raw[0] ^= 1
        bad_sig = os.path.join(temp_dir, 'bad.sig')
        for label, mutate in (
            ("modified signature", lambda d: d.update(signature=base64.b64encode(bytes(raw)).decode())),
            ("unsupported version", lambda d: d.update(version=99)),
            ("unsupported algorithm", lambda d: d.update(algorithm="RSA")),
        ):
            changed = dict(doc); mutate(changed)
            with open(bad_sig, 'wb') as f:
                f.write(json.dumps(changed).encode())
            assert nx.verify_file(src, bad_sig, pub) is False, f"{label} was not detected"
        with open(bad_sig, 'wb') as f:
            f.write(b"not a signature")
        assert nx.verify_file(src, bad_sig, pub) is False, "Garbage signature file accepted"

        # another signer's key, with and without the fingerprint hint
        other_dir = os.path.join(temp_dir, 'other')
        _, other_pub, _ = self._signing_setup(other_dir)
        assert nx.verify_file(src, sig, other_pub) is False, "Signature accepted with the wrong key"
        no_hint = dict(doc); del no_hint["key_fingerprint"]
        with open(bad_sig, 'wb') as f:
            f.write(json.dumps(no_hint).encode())
        assert nx.verify_file(src, bad_sig, other_pub) is False, "Wrong key accepted when the fingerprint is absent"
        assert nx.verify_file(src, bad_sig, pub) is True, "The fingerprint must be optional for a valid signature"

        # wrong password: nothing written
        sig2 = os.path.join(temp_dir, 'never.sig')
        assert nx.sign_file(src, priv, "wrong", sig2) is False, "Signing worked with a wrong password"
        assert not os.path.exists(sig2) and not os.path.exists(sig2 + '.part'), "Partial signature left behind"
        assert nx.sign_file(os.path.join(temp_dir, 'missing.bin'), priv, "test_password123", sig2) is False, \
            "Signing a missing file reported success"
        assert not os.path.exists(sig2), "Signature written for a missing file"

        # empty files can be signed
        empty = os.path.join(temp_dir, 'empty.bin')
        open(empty, 'wb').close()
        assert nx.sign_file(empty, priv, "test_password123"), "Signing an empty file failed"
        assert nx.verify_file(empty, empty + '.sig', pub) is True, "Empty file signature rejected"

    def test_signature_key_type_checks(self, temp_dir):
        """RSA keys cannot sign and Ed25519 keys cannot encrypt (clear errors, no output)"""
        rsa_dir = os.path.join(temp_dir, 'rsa')
        rsa_nx, rsa_pub, rsa_priv = self._setup_keys(rsa_dir)
        nx, ed_pub, ed_priv = self._signing_setup(os.path.join(temp_dir, 'ed'))
        src = os.path.join(temp_dir, 'f.bin')
        with open(src, 'wb') as f:
            f.write(b"content")

        out = os.path.join(temp_dir, 'rsa.sig')
        assert nx.sign_file(src, rsa_priv, "test_password123", out) is False, "RSA key was accepted for signing"
        assert not os.path.exists(out), "Signature written with an RSA key"
        assert nx.sign_file(src, ed_priv, "test_password123"), "Signing failed"
        assert nx.verify_file(src, src + '.sig', rsa_pub) is False, "RSA key accepted for verification"
        assert nx.encrypt_data(b"x", ed_pub) is None, "Ed25519 key accepted for encryption"
        encrypted = rsa_nx.encrypt_data(b"x", rsa_pub)
        assert nx.decrypt_data(bytes.fromhex(encrypted), ed_priv, "test_password123") is None, \
            "Ed25519 key accepted for decryption"

    def test_signature_all_key_formats(self, temp_dir):
        """Signing keys work in every format, with auto-detection and OpenSSH public keys"""
        src = os.path.join(temp_dir, 'f.bin')
        with open(src, 'wb') as f:
            f.write(b"formats")
        for key_format in (KeyFormat.PEM, KeyFormat.DER, KeyFormat.JSON, KeyFormat.SSH):
            sub = os.path.join(temp_dir, key_format.lower())
            nx, pub, priv = self._signing_setup(sub, key_format)
            sig = os.path.join(sub, 'f.sig')
            assert nx.sign_file(src, priv, "test_password123", sig), f"Signing failed with {key_format} keys"
            assert nx.verify_file(src, sig, pub), f"Verification failed with {key_format} keys"
            if key_format != KeyFormat.SSH:
                assert nx.sign_file(src, priv, "test_password123", sig, key_format), \
                    f"Explicit {key_format} format rejected"

        pem_dir = os.path.join(temp_dir, 'pem')
        pem_pub = open(os.path.join(pem_dir, 'signing_public_key.pem'), 'rb').read()
        ssh_pub = KeyConverter.convert_public_key(pem_pub, KeyFormat.PEM, KeyFormat.SSH)
        assert ssh_pub.startswith(b"ssh-ed25519 "), "Ed25519 public key not exported as ssh-ed25519"
        ssh_path = os.path.join(temp_dir, 'converted.ssh')
        with open(ssh_path, 'wb') as f:
            f.write(ssh_pub)
        assert nx.verify_file(src, os.path.join(pem_dir, 'f.sig'), ssh_path), \
            "Signature not verifiable with the converted OpenSSH key"

    def test_sign_data_api(self, temp_dir):
        """Raw bytes can be signed and verified"""
        nx, pub, priv = self._signing_setup(temp_dir)
        for payload in (b"hello", b"", os.urandom(10000)):
            signature = nx.sign_data(payload, priv, "test_password123")
            assert signature, "sign_data failed"
            assert nx.verify_data(payload, signature, pub) is True, "Valid data signature rejected"
            assert nx.verify_data(payload + b"!", signature, pub) is False, "Modified data accepted"
        assert nx.sign_data(b"x", priv, "wrong") is None, "sign_data worked with a wrong password"

    def test_signature_cli(self, temp_dir):
        """signkeygen / sign / verify through the CLI handlers, with exit-code semantics"""
        keys = os.path.join(temp_dir, 'keys')
        result, _ = self._run_cli(dict(command='signkeygen', output=keys, password="test_password123", format='PEM'))
        assert result is True, "signkeygen failed"
        priv = os.path.join(keys, 'signing_private_key.pem')
        pub = os.path.join(keys, 'signing_public_key.pem')
        src = os.path.join(temp_dir, 'cli.txt')
        with open(src, 'wb') as f:
            f.write(b"cli content")

        result, _ = self._run_cli(dict(command='sign', input=src, output=None, key=priv,
                                       password="test_password123", key_format=None))
        assert result is True and os.path.exists(src + '.sig'), "sign failed"
        result, _ = self._run_cli(dict(command='verify', input=src, signature=None, key=pub, key_format=None))
        assert result is True, "verify rejected a valid signature"

        with open(src, 'wb') as f:
            f.write(b"cli content, modified")
        result, _ = self._run_cli(dict(command='verify', input=src, signature=None, key=pub, key_format=None))
        assert result is False, "verify accepted a modified file"
        result, _ = self._run_cli(dict(command='sign', input=src, output=None, key=priv,
                                       password="wrong", key_format=None))
        assert result is False, "sign accepted a wrong password"

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