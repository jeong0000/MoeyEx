import datetime
import struct
from Crypto.Cipher import ChaCha20
import binascii
import json, re
import pycryptonight
from datetime import datetime, timezone
import argparse

def generate_chacha_key(data, size, key, kdf_rounds):
    """
    Generate a ChaCha20 key using the provided password and KDF (Key Derivation Function)
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

def decrypt_file(password):
    """
    Decrypt a file using ChaCha20 algorithm.
    :param file_path: Path to the encrypted file
    :param password: Password for decryption (string)
    :return: Decrypted data (bytes or hex string)
    """
    try:
        result = bytearray(64)
        generate_chacha_key(password, len(password), result, kdf_rounds=1)  # Generate key using password
        #key = binascii.unhexlify(key_hex)  # Convert key to binary
        key = bytes(result[:32])  # Use only the first 32 bytes of the key

        # Read file in binary mode
        with open(file_path, "rb") as f:
            file_data = f.read()

            # Extract IV (00-07 bytes)
            iv_hex = file_data[:8].hex()
            iv = binascii.unhexlify(iv_hex)

            # Extract encrypted data (0A byte onward)
            encrypted_hex = file_data[10:].hex()
            encrypted_data = binascii.unhexlify(encrypted_hex)

        # Create ChaCha20 decryption object
        cipher = ChaCha20.new(key=key, nonce=iv)
        
        # Perform decryption
        decrypted_data = cipher.decrypt(encrypted_data)
        #return decrypted_data.decode('utf-8', errors='ignore')
        return decrypted_data.hex()
    except Exception as e:
        return f"Error during decryption: {str(e)}"

# key data parsing
def parse_key_data(data):
    result = {}
    
    # 1. m_creation_timestamp 찾고 파싱
    creation_timestamp_index = data.find(b'm_creation_timestamp') + len(b'm_creation_timestamp') + 1
    creation_timestamp = struct.unpack('<Q', data[creation_timestamp_index:creation_timestamp_index + 8])[0]
    result['creation timestamp'] = datetime.fromtimestamp(creation_timestamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    
    # 2. m_spend_public_key 찾고 파싱
    spend_public_key_index = data.find(b'm_spend_public_key') + len(b'm_spend_public_key') + 2
    spend_public_key = data[spend_public_key_index:spend_public_key_index + 32]
    result['spend public key'] = spend_public_key.hex()
    
    # 3. m_view_public_key 찾고 파싱
    view_public_key_index = data.find(b'm_view_public_key') + len(b'm_view_public_key') + 2
    view_public_key = data[view_public_key_index:view_public_key_index + 32]
    result['view public key'] = view_public_key.hex()
    
    # 4. m_encryption_iv 찾고 파싱
    encryption_iv_index = data.find(b'm_encryption_iv') + len(b'm_encryption_iv') + 2
    encryption_iv = data[encryption_iv_index:encryption_iv_index + 8]
    result['encryption iv'] = encryption_iv.hex()
    
    # 5. m_spend_secret_key 찾고 파싱
    spend_secret_key_index = data.find(b'm_spend_secret_key') + len(b'm_spend_secret_key') + 2
    spend_secret_key = data[spend_secret_key_index:spend_secret_key_index + 32]
    result['spend secret key'] = spend_secret_key.hex()
    
    # 6. m_view_secret_key 찾고 파싱
    view_secret_key_index = data.find(b'm_view_secret_key') + len(b'm_view_secret_key') + 2
    view_secret_key = data[view_secret_key_index:view_secret_key_index + 32]
    result['view secret key'] = view_secret_key.hex()
    
    return result

def decrypt_secret_key(encrypted_key, key_stream, flag):
    # Convert hex strings to byte arrays
    encrypted_key_bytes = bytes.fromhex(encrypted_key)
    key_stream_bytes = key_stream

    # If key_stream is longer than 32 bytes, truncate it to 32 bytes
    #if len(key_stream_bytes) > 32:
    #    #key_stream_bytes = key_stream_bytes[:32]
    #    key_stream_bytes = key_stream_bytes[32:]
    if flag == 1:
        key_stream_bytes = key_stream_bytes[:32]
    else:
        key_stream_bytes = key_stream_bytes[32:]

    # Perform XOR operation byte by byte
    original_key_bytes = bytes([e ^ k for e, k in zip(encrypted_key_bytes, key_stream_bytes)])

    # Convert the result back to a hex string
    return original_key_bytes.hex()

#file_path = input("Enter the file path: ")  # Path to the encrypted file
#password = input("Enter the password: ")  # Prompt user for password

parser = argparse.ArgumentParser(description="Monero key file decryptor")
parser.add_argument('--file', '-f', required=True, help='Path to the encrypted .keys file')
parser.add_argument('--password', '-p', required=True, help='Password for the .keys file')
args = parser.parse_args()

file_path = args.file
password = args.password

# Perform decryption
decrypted_data = decrypt_file(password)

try:
    # hex -> bytes 
    bytes_data = bytes.fromhex(decrypted_data)

    # bytes -> Latin-1 decoding
    json_str = bytes_data.decode('latin1')

    # JSON parsing
    parsed_data = json.loads(json_str)

    key_data_str = parsed_data['key_data'].encode('latin1')
    parsed_data['key_data'] = parse_key_data(key_data_str)

    result_key = bytearray(64)      
    chacha_key = generate_chacha_key(password, len(password), result_key, 1)
    
    # Check if the last 32 bytes are all zeros
    if all(byte == 0 for byte in result_key[32:]):
        # If true, keep only the first 32 bytes
        result_key = result_key[:32]

    key_stream = get_key_stream(result_key, binascii.unhexlify(parsed_data["key_data"]["encryption iv"]), 64)

    parsed_data["key_data"]["spend secret key"] = decrypt_secret_key(parsed_data["key_data"]["spend secret key"], key_stream, 1)
    parsed_data["key_data"]["view secret key"] = decrypt_secret_key(parsed_data["key_data"]["view secret key"], key_stream, 0)

    # result
    print(json.dumps(parsed_data, indent=2, ensure_ascii=False))
except json.JSONDecodeError as e:
    print("Error decoding JSON:", e)
    print("Raw Decrypted Data:", decrypted_data)
