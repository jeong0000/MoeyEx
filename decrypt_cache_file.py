from Crypto.Cipher import ChaCha20
import pycryptonight
from datetime import datetime, timezone
import argparse
import csv, os

class ProcessingContext:
    """Handles binary data processing with position tracking"""
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.tx_count = 0
        self.storage = {
            'transactions': [],
            'tx_keys': {} 
        }

    def read_varint(self):
        """Decodes varint and returns (value, bytes_consumed)"""
        value = 0
        shift = 0
        start_pos = self.pos
        while self.pos < len(self.data):
            byte = self.data[self.pos]
            value |= (byte & 0x7F) << shift
            self.pos += 1
            if not (byte & 0x80):
                break
            shift += 7
        return value, self.pos - start_pos

    def skip(self, n):
        """Moves position by N bytes"""
        self.pos += n
        return self

def m_blockchain(ctx):
    """Processes blockchain hsah list"""
    # Step 1: VERSION_FIELD(0)
    ctx.skip(1)

    # Step 2: VARINT_FIELD(m_offset)
    val1, bytes_used = ctx.read_varint()

    # Step 3: FIELD(m_genesis)
    ctx.skip(32)

    # Step 4: FIELD(m_blockchain) -> hashlist count
    tmp, bytes_used = ctx.read_varint()

    # Step 5: FIELD(m_blockchain) -> hashlist
    final_offset = ctx.pos + (tmp * 32)
    ctx.pos = final_offset

    return final_offset

def m_tx(ctx):
    """Processes transaction data"""
    # Step 1-2: VARINT_FIELD(version), VARINT_FIELD(unlock_time)
    for i in range(1, 3):
        value, bytes_used = ctx.read_varint()
        #print(f"[TX Step {i}] VARINT value: {value}, Bytes: {bytes_used}, Offset: 0x{ctx.pos:X}")
    
    # Step 3-6: Vin count(1) -> [Vin variant tag(02: txin_to_key), VARINT_FIELD(amount)(0), FIELD(key_offsets) - ring size(0x10)]
    for i in range(3, 7):
        ctx.skip(1)
        #print(f"[TX Step {i}] Skipped 1 byte, Offset: 0x{ctx.pos:X}")
    
    # Step 7: FIELD(key_offsets) - values
    for i in range(7, 23):  # 16 varints
        value, bytes_used = ctx.read_varint()
        #print(f"[TX Step {i}] Key offset VARINT: {value}, Bytes: {bytes_used}, Offset: 0x{ctx.pos:X}")
    
    # Step 8-19: FIELD(k_image), 
    # Step 9-17: vout_count(2) -> [VARINT_FIELD(amount)(0), Vout variant tag(03: txout_to_tagged_key), FIELD(key) - public_key(32), FIELD(view_tag)(1)]
    # Step 18-19: FIELD(extra) - [1, 44]
    skip_pattern = [32,1,1,1,32,1,1,1,32,1,1,44]
    public_keys = []
    for idx, n in enumerate(skip_pattern, start=23):
        if idx == 27 or idx == 31:  # 32바이트 public key 위치 (4,8번째 32바이트)
            pub_key_bytes = ctx.data[ctx.pos:ctx.pos+32]
            public_keys.append(pub_key_bytes.hex())
            ctx.skip(n)
        else:
            ctx.skip(n)

    while len(public_keys) < 2:
        public_keys.append("-")

    return public_keys
    '''
    for idx, n in enumerate(skip_pattern, start=23):
        ctx.skip(n)
        #print(f"[TX Step {idx}] Skipped {n} bytes, Offset: 0x{ctx.pos:X}")
    '''

def m_transfers(ctx):
    """Processes transfer records"""
    tx_count, _ = ctx.read_varint()
    ctx.tx_count = tx_count  
    #print(f"[m_transfers] Transaction count: {tx_count} at 0x{ctx.pos:X}")
    
    # FIELD(m_txid)(32), FIELD(m_internal_output_index)(8), FIELD(m_global_output_index)(8), FIELD(m_spent)(1), FIELD(m_frozen)(1), FIELD(m_spent_height)(8), FIELD(m_key_image)(32), FIELD(m_mask)(32)
    # FIELD(m_amount)(8), FIELD(m_rct)(1), FIELD(m_key_image_known)(1), FIELD(m_key_image_request)(1), FIELD(m_pk_index)(8), FIELD(m_subaddr_index)(8), FIELD(m_key_image_partial)(1)
    # FIELD(m_multisig_k)(1), FIELD(m_multisig_info)(1) ->  multisig use X / FIELD(m_uses)(1) -> output usage record X
    post_tx_skips = [32,8,8,1,1,8,32,32,8,1,1,1,8,8,1,1,1,1]

    for _ in range(tx_count):
        ctx.skip(8)  # Transaction block height
        m_tx(ctx)    # Process transaction
        
        # Apply post-transaction skips
        for n in post_tx_skips:
            ctx.skip(n)

def m_account_public_address(ctx):
    """Processes pulic address"""
    # Public spend key(32), public view key(32)
    for _ in range(2):
        ctx.skip(32)  # Transaction block height

def m_key_images(ctx):
    """Processes key images"""
    # Key image count  = tx_count
    key_image_count = ctx.tx_count

    for _ in range(key_image_count):
        count, _ = ctx.read_varint()
        ctx.skip(1)     # (02)
        ctx.skip(32)    # key image

def m_unconfirmed_txs(ctx):
    """Processes unconfirmed transactions""" 
    ctx.skip(2) # unconfirmed tx X(0)

def m_payments(ctx):
    """Processes payments -> Receiving transactions"""
    # Receiving tx count
    rv_tx_count, _ = ctx.read_varint()

    for _ in range(rv_tx_count):
        ctx.skip(1)     # (02)
        ctx.skip(32)    # key image
        ctx.skip(1)     # VERSION_FIELD(0)

        tx_id = ctx.data[ctx.pos:ctx.pos+32].hex()
        ctx.skip(32)    # FIELD(m_payments) - tx id

        amount, _ = ctx.read_varint() # VARINT_FIELD(m_amount)

        amounts_count, _ = ctx.read_varint()    # VARINT_FIELD(m_amounts)
        for _ in range(amounts_count):
            amounts, _ = ctx.read_varint()

        fee, _ = ctx.read_varint()          # FIELD(m_fee)
        bc_height, _ = ctx.read_varint()    # VARINT_FIELD(m_block_height)

        unlock_time, _ = ctx.read_varint()    # VARINT_FIELD(m_unlock_time)
        timestamp, _ = ctx.read_varint()    # VARINT_FIELD(m_timestamp)
        ctx.skip(1)                         # FIELD(m_coinbase)
        ctx.skip(8)                         # FIELD(m_subaddr_index) ->  subaddress X

        # tx stroage
        ctx.storage['transactions'].append({
            'type': "in",
            'timestamp': timestamp,
            'block_height': bc_height,
            'tx_id': tx_id,
            'tx_key': "-",
            'amount':amount,
            'fee': fee,
            'change': "-",
            'destination_address': "-"
        })

def m_tx_keys(ctx):
    """Processes tx_keys -> Sending transactions"""
    # Sending tx count
    s_tx_count, _ = ctx.read_varint()

    for _ in range(s_tx_count):
        ctx.skip(1)     # (02)
        tx_id = ctx.data[ctx.pos:ctx.pos+32].hex()
        ctx.skip(32)    # tx id

        tx_key = ctx.data[ctx.pos:ctx.pos+32].hex()
        ctx.skip(32)    # tx key

        ctx.storage['tx_keys'][tx_id] = tx_key

def m_confirmed_txs(ctx):
    """Processes confirmed_txs -> Sending transactions"""
    # Sending tx count
    s_tx_count, _ = ctx.read_varint()

    for _ in range(s_tx_count):
        ctx.skip(1)     # (02)
        tx_id = ctx.data[ctx.pos:ctx.pos+32].hex()
        ctx.skip(32)    # tx id
        ctx.skip(1)     # VERSION_FIELD(1)
        
        public_keys = m_tx(ctx)  # Return value received: 2 public keys list
        #m_tx(ctx)
        
        amount_in, _ = ctx.read_varint()    # VARINT_FIELD(m_amount_in)
        amount_out, _ = ctx.read_varint()   # VARINT_FIELD(m_amount_out)
        change, _ = ctx.read_varint()       # VARINT_FIELD(m_change)
        bc_height, _ = ctx.read_varint()    # VARINT_FIELD(m_block_height)

        ctx.skip(1)                         # FIELD(m_dests) -> FIELD(original) -> Vector count(01)
        ctx.skip(1)                         # FIELD(m_dests) -> FIELD(original) -> length(0x5F)
        des_address = ctx.data[ctx.pos:ctx.pos+95].hex()
        ctx.skip(95)                        # Destination address 
        amount, _ = ctx.read_varint()       # VARINT_FIELD(m_amount)

        ctx.skip(32)                        # FIELD(addr) -> destination public spend key 
        ctx.skip(32)                        # FIELD(addr) -> destination public view key 

        ctx.skip(1)                         # FIELD(is_subaddress) -> Subaddress status
        ctx.skip(1)                         # FIELD(is_integrated) -> Integrated address status 

        ctx.skip(32)                        # FIELD(m_payment_id)
        timestamp, _ = ctx.read_varint()    # VARINT_FIELD(m_unlock_time)
        unlock_time, _ = ctx.read_varint()  # VARINT_FIELD(m_timestamp)
        ctx.skip(1)                         # VARINT_FIELD(m_subaddr_account) -> subaddress X
        ctx.skip(2)                         # FIELD(m_subaddr_indices) -> subaddress X

        ctx.skip(1)                         # FIELD(m_rings)(01)
        ctx.skip(1)                         # FIELD(m_rings)(02)
        ctx.skip(32)                        # FIELD(m_rings) -> key image
        ctx.skip(1)                         # FIELD(m_rings) -> ring size(0x10)
        for i in range(0, 16):  # 16 varints
            value, bytes_used = ctx.read_varint()

        tx_key = ctx.storage['tx_keys'].get(tx_id, "-")
        # fee 
        fee = amount_in - amount_out if (amount_in is not None and amount_out is not None) else "-"
        # destination_address -> string
        des_addr_str = bytes.fromhex(des_address).decode('utf-8')

        ctx.storage['transactions'].append({
            'type': "out",
            'timestamp': timestamp,  
            'block_height': bc_height,
            'tx_id': tx_id,
            'tx_key': tx_key,
            'amount': amount,
            'fee': fee,
            'change': change,
            'destination_address': des_addr_str,
            'public_key_1': public_keys[0],
            'public_key_2': public_keys[1],
        })

def process_file(data):
    """Main file processing function"""
    #with open(file_path, 'rb') as f:
    #    data = f.read()
    
    ctx = ProcessingContext(data)
    
    # Initial 20-byte skip -> MAGIC_FIELD("monero wallet cache") + VERSION_FIELD(2)
    ctx.skip(20)
    #print(f"[Initial offset] 0x{ctx.pos:X}")
    
    m_blockchain(ctx)  # Process blockchain
    #print(f"m_blockchain Offset: 0x{ctx.pos:X}")
    m_transfers(ctx)   # Process transfers
    #print(f"m_transfers Offset: 0x{ctx.pos:X}")
    m_account_public_address(ctx)  # Process public address
    #print(f"m_account_public_address Offset: 0x{ctx.pos:X}")
    m_key_images(ctx)  # Process key images
    #print(f"m_key_images Offset: 0x{ctx.pos:X}")
    m_unconfirmed_txs(ctx)  # Process unconfirmed transactions
    #print(f"m_unconfirmed_txs Offset: 0x{ctx.pos:X}")
    m_payments(ctx)  # Process payments
    #print(f"m_payments Offset: 0x{ctx.pos:X}")
    m_tx_keys(ctx)  # Process tx keys
    #print(f"m_tx_keys Offset: 0x{ctx.pos:X}")
    m_confirmed_txs(ctx)  # Process confirmed transactions
    #print(f"m_confirmed_txs Offset: 0x{ctx.pos:X}")
    
    #print(f"Final Offset: 0x{ctx.pos:X}")
    
    print("\n***Transactions Summary***")
    print("{:<4} {:<19} {:<12} {:<64} {:<64} {:<12} {:<8} {:<12} {:<40} {:<64} {:<64}".format(
        "Type", "Timestamp", "BlockHeight", "TX ID", "TX Key", "Amount", "Fee", "Change", "Destination Address", "Public Key 1", "Public Key 2"
    ))
    sorted_txs = sorted(ctx.storage['transactions'], key=lambda x: x['timestamp'])
    
    for tx in sorted_txs:
        #dt = datetime.utcfromtimestamp(tx['timestamp'])
        dt = datetime.fromtimestamp(tx['timestamp'], tz=timezone.utc)
        # amount, fee, change -> piconero
        def show_xmr(val):
            try:
                return f"{int(val) / 1_000_000_000_000:.12f}"
            except:
                return "-"
        print("{:<4} {:<19} {:<12} {:<64} {:<64} {:<12} {:<8} {:<12} {:<40} {:<64} {:<64}".format(
            tx['type'],
            dt.strftime("%Y-%m-%d %H:%M:%S"),
            tx['block_height'],
            tx['tx_id'],
            tx['tx_key'],
            show_xmr(tx['amount']),
            show_xmr(tx['fee']),
            show_xmr(tx['change']),
            tx['destination_address'],
            tx.get('public_key_1', "-"),
            tx.get('public_key_2', "-")
        ))
        #print("\n")
        
    # Save CSV file to current directory as 'transaction_result.csv'
    csv_filename = "transaction_result.csv"

    with open(csv_filename, mode='w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            "Type", "Timestamp", "BlockHeight", "TX ID", "TX Key", "Amount", "Fee", "Change", "Destination Address", "Public Key 1", "Public Key 2"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for tx in sorted_txs:
            dt = datetime.fromtimestamp(tx['timestamp'], tz=timezone.utc)
            writer.writerow({
                "Type": tx['type'],
                "Timestamp": dt.strftime("%Y-%m-%d %H:%M:%S"),
                "BlockHeight": tx['block_height'],
                "TX ID": tx['tx_id'],
                "TX Key": tx['tx_key'],
                "Amount": show_xmr(tx['amount']),
                "Fee": show_xmr(tx['fee']),
                "Change": show_xmr(tx['change']),
                "Destination Address": tx['destination_address'],
                "Public Key 1": tx.get('public_key_1', "-"),
                "Public Key 2": tx.get('public_key_2', "-"),
            })
    
    print(f"\nTransaction data has been saved to '{csv_filename}' in the current directory.")

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


def derive_cache_key(keys_data_key: bytes, domain_separator: int = 0x8d) -> bytes:
    """
    Monero wallet cache file -  derive ChaCha20 key
    """
    if len(keys_data_key) != 32:
        raise ValueError("keys_data_key must be 32 bytes long.")
    if not (0 <= domain_separator <= 255):
        raise ValueError("domain_separator must be a single byte (0-255).")

    cache_key_data = bytearray(33)
    cache_key_data[0:32] = keys_data_key
    cache_key_data[32] = domain_separator

    cache_key = pycryptonight.cn_fast_hash(bytes(cache_key_data))
    #print(f"Cache Key: {cache_key.hex()}")  # Debugging line to check the derived cache key
    return cache_key[:32]

def decrypt_file(password):
    """
    Decrypt Monero wallet cache file (ChaCha20)
    """
    result = bytearray(64)
    generate_chacha_key(password, len(password), result, kdf_rounds=1)  # Generate key using password
    cache_key = derive_cache_key(result[:32], 0x8d)  # Monero domain seperator
    key = bytes(cache_key[:32])  # Use only the first 32 bytes of the key

    with open(file_path, "rb") as f:
        file_data = f.read()
        iv = file_data[0:8]           # 0~7: IV
        
        ctx = ProcessingContext(file_data)
        ctx.pos = 8  # varint start
        varint_value, bytes_used = ctx.read_varint()  

        encrypted_data = file_data[ctx.pos:] 

    cipher = ChaCha20.new(key=key, nonce=iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data

if __name__ == "__main__":
    #file_path = input("Enter the file path: ").strip()
    #password = input("Enter the password: ").strip()

    parser = argparse.ArgumentParser(description="Monero key file decryptor")
    parser.add_argument('--file', '-f', required=True, help='Path to the encrypted .keys file')
    parser.add_argument('--password', '-p', required=True, help='Password for the .keys file')
    args = parser.parse_args()

    file_path = args.file
    password = args.password

    try:
        decrypted_data = decrypt_file(password)
        process_file(decrypted_data)
    except Exception as e:
        print(f"Error during decryption: {e}")