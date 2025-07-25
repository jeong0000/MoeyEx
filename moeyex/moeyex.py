from volatility3.framework.configuration import requirements
from volatility3.framework import interfaces, renderers
from concurrent.futures import ProcessPoolExecutor
import mmap, os, struct
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.request import url2pathname

from nacl.bindings import crypto_scalarmult_ed25519_base_noclamp
from Crypto.Cipher import ChaCha20
import pycryptonight

def generate_public_key(secret_key_bytes):
    if len(secret_key_bytes) != 32:
        raise ValueError("Secret key must be 32 bytes long")
    return crypto_scalarmult_ed25519_base_noclamp(secret_key_bytes).hex()

def is_valid_structure(data):
    try:
        spend_public_key = data[:32]
        view_public_key = data[32:64]
        spend_secret_key = data[64:96]
        view_secret_key = data[96:128]
        #multisig_keys = data[128:152]
        multisig_keys = struct.unpack('<Q', data[136:144])[0]
        device_ptr = data[152:160]
        encryption_iv = data[160:168]
        creation_timestamp = struct.unpack("Q", data[168:176])[0]

        if all(b == 0 for b in spend_public_key) and all(b == 0 for b in view_public_key) and all(b == 0 for b in spend_secret_key) and all(b == 0 for b in view_secret_key) and all(b == 0 for b in device_ptr) and all(b == 0 for b in encryption_iv):
            return False

        # UTC timestamp -> datetime
        creation_datetime = datetime.fromtimestamp(creation_timestamp, tz=timezone.utc)
        # to KST (UTC + 9)
        cutoff_date = datetime(2014, 4, 18, tzinfo=timezone.utc)

        if creation_datetime < cutoff_date:
            return False
        
        computed_view_public_key = generate_public_key(view_secret_key)
        
        if computed_view_public_key != view_public_key.hex():
            return False
        
        return {
            "spend_public_key": spend_public_key.hex(),
            "view_public_key": view_public_key.hex(),
            "spend_secret_key": spend_secret_key.hex(),
            "view_secret_key": view_secret_key.hex(),
            "multisig_keys": multisig_keys,
            "encryption_iv": encryption_iv,
            "creation_time": creation_datetime.strftime("%Y-%m-%d %H:%M:%S")
        }
    except Exception:
        return False

def process_chunk(mdmp_path, start, end):
    valid = []
    with open(mdmp_path, "rb") as f:
        mmapped_file = mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ)
        for offset in range(start, end - 176, 8):
            block = mmapped_file[offset:offset + 176]
            result = is_valid_structure(block)
            if result:
                valid.append(result)
    return valid

def generate_chacha_key(data, size, key, kdf_rounds):
    """
    param data: input data (bytes)
    param size: data size (int)
    param key: output key (bytearray)
    param kdf_rounds: 1 (int)
    """
    # Convert String to Bytes
    if isinstance(data, str):
        data = data.encode('utf-8')  # String -> UTF-8 bytes

    # Convert data to bytes to ensure compatibility with pycryptonight
    data = bytes(data)  # Convert bytearray to bytes

    # Initial hash calculation (variant=0, prehashed=0, height=0)
    pwd_hash = pycryptonight.cn_slow_hash(data, variant=0, prehashed=0, height=0)

    # Perform additional KDF rounds
    for _ in range(1, kdf_rounds):
        pwd_hash = pycryptonight.cn_slow_hash(pwd_hash, variant=0, prehashed=0, height=0)

    # Copy the final hash value to the key
    key[:32] = pwd_hash[:32]  # Copy only the first 32 bytes

def derive_key(base_key):
    """
    param base_key: input key (bytes)
    return: derived key (bytes)
    """
    if len(base_key) != 32:
        raise ValueError("base_key must be 32 bytes")

    # Combine base_key with additional data ('k')
    data = bytearray(base_key)
    data.append(ord('k'))  # Add ASCII value of 'k'

    # Generate the ChaCha key
    key = bytearray(32)
    generate_chacha_key(bytes(data), len(data), key, kdf_rounds=1)
    return bytes(key)

def get_key_stream(base_key, iv, bytes):
    """
    param base_key: input key (bytes)
    param iv: m_encryption_iv (bytes)
    param bytes: m_multisig_keys (int)
    return: ChaCha20 Encryption Results (bytes)
    """
    if len(iv) != 8:
        raise ValueError("IV must be 8 bytes")

    # Derive a new key
    key = derive_key(base_key)

    # Initialize buffer with null bytes
    buffer = bytearray(bytes)

    # Perform ChaCha20 encryption
    cipher = ChaCha20.new(key=key, nonce=iv)
    result = cipher.encrypt(buffer)

    # Check if the last 32 bytes are all zeros
    if all(byte == 0 for byte in result[32:]):
        # If true, keep only the first 32 bytes
        result = result[:32]

    return result

def decrypt_spend_secret_key(encrypted_key, key_stream):
    # Convert hex strings to byte arrays
    encrypted_key_bytes = bytes.fromhex(encrypted_key)
    key_stream_bytes = key_stream

    # If key_stream is longer than 32 bytes, truncate it to 32 bytes
    if len(key_stream_bytes) > 32:
        key_stream_bytes = key_stream_bytes[:32]

    # Perform XOR operation byte by byte
    original_key_bytes = bytes([e ^ k for e, k in zip(encrypted_key_bytes, key_stream_bytes)])

    # Convert the result back to a hex string
    return original_key_bytes.hex()

class moeyex(interfaces.plugins.PluginInterface):
    """Extract keys from Monero memory dump file."""
    
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.URIRequirement(
                name='file-path',
                description='Path to the Monero memory dump file',
                optional=True
            ),
                requirements.StringRequirement(
                name='passphrase',
                description='Passphrase for the Monero wallet',
                optional=False
            )
        ]

    def run(self):
        file_path = self.config.get('file-path', self.config.get('location'))
        if not file_path or file_path == "memory":
            raise ValueError("Valid file path required")
        file_path = urlparse(file_path)
        file_path = url2pathname(file_path.path)
        passphrase = self.config.get('passphrase')
        

        file_size = os.path.getsize(file_path)

        # Chunk division
        chunk_size = 10 * 1024 * 1024
        chunks = [(file_path, i, min(i + chunk_size, file_size)) for i in range(0, file_size, chunk_size)]

        # parallel processing
        with ProcessPoolExecutor() as executor:
            results = executor.map(process_chunk, *zip(*chunks))

        # Merge Results
        valid_entries = []
        for sublist in results:
            for item in sublist:
                if ("spend_secret_key" in item):
                    if item["spend_public_key"] != generate_public_key(bytes.fromhex(item["spend_secret_key"])):
                        monero_spend_secret_key = item["spend_secret_key"]
                        iv = item["encryption_iv"]
                        length = 32 * (2 + item["multisig_keys"])
                        #length = 64

                        result_key = bytearray(64)
                        
                        # Output the modified result_key
                        generate_chacha_key(passphrase, len(passphrase), result_key, 1)

                        # Check if the last 32 bytes are all zeros
                        if all(byte == 0 for byte in result_key[32:]):
                            # If true, keep only the first 32 bytes
                            result_key = result_key[:32]

                        key_stream = get_key_stream(result_key, iv, length)

                        # Decrypt the original spend secret key
                        original_spend_secret_key = decrypt_spend_secret_key(monero_spend_secret_key, key_stream)
                        
                        item["spend_secret_key"] = original_spend_secret_key

                valid_entries.append(item)

        return renderers.TreeGrid(
            [("Key", str), ("Value", str)],
            self._generator(valid_entries)
        )
    
    def _generator(self, data):
        for entry in data:
            yield (0, ("Public Spend Key", entry["spend_public_key"]))
            yield (0, ("Public View Key", entry["view_public_key"]))
            yield (0, ("** Private Spend Key", entry["spend_secret_key"]))
            yield (0, ("Private View Key", entry["view_secret_key"]))
            #yield (0, ("multisig_keys", str(entry["multisig_keys"])))
            #yield (0, ("encryption_iv", entry["encryption_iv"].hex()))
            yield (0, ("Creation Time", entry["creation_time"]))