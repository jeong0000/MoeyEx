# MoeyEx
A Volatility 3 plugin for extracting Monero’s account base instances.

(Monero stores wallet-related key data in the account_base instance)

## Features
MoeyEx extracts key values(Public/Private keys) from memory dump files.

The output data is as:

- Public Spend Key 
- Public View Key 
- Private Spend Key  
- Private View Key 
- Creation Time

## Use instructions
1. py-cryptonight install
   - Run cmd in the py-cryptonite folder
   ```
    python setup.py install
   ```
2. Save moeyex folder in the location below
   - \volatility3\volatility3\plugins\
3. Run moeyex plugin
   ```
   python vol.py moeyex --file-path=<file-path> --passphrase=<wallet-password>
   ```

# Decrypt wallet keys file
The wallet keys file encrypts and stores key values and wallet-related setting data.

## Features
decrypt_keys_file.py extracts key data(Public/Private keys) and 49 wallet-related setting data from &lt;walletname&gt;.keys file.

The output data is as:

"key_data": {
    "creation timestamp", "spend public key", "view public key", "encryption iv", "spend secret key", "view secret key"
},
  
"seed_language", "key_on_device", "watch_only", "multisig", "multisig_threshold", "always_confirm_transfers", "print_ring_members", "store_tx_info", "default_mixin", "default_priority", "auto_refresh", "refresh_type", "refresh_height", "skip_to_height", "confirm_non_default_ring_size", "ask_password", "max_reorg_depth", "min_output_count", "min_output_value", "default_decimal_point", "merge_destinations", "confirm_backlog", "confirm_backlog_threshold",
"confirm_export_overwrite", "auto_low_priority", "nettype", "segregate_pre_fork_outputs", "key_reuse_mitigation2", "segregation_height", "ignore_fractional_outputs", "ignore_outputs_above", "ignore_outputs_below", "track_uses", "background_sync_type", "show_wallet_name_when_locked", "inactivity_lock_timeout", "setup_background_mining", "subaddress_lookahead_major", "subaddress_lookahead_minor", "original_keys_available", "export_format", "load_deprecated_formats", "encrypted_secret_keys", "device_name", "device_derivation_path", "persistent_rpc_client_id", "auto_mine_for_rpc_payment", "credits_target", "enable_multisig"

## Use instructions
1. py-cryptonight install
   - Run cmd in the py-cryptonite folder
   ```
    python setup.py install
   ```
2. Run decrypt_keys_file.py
   ```
    python decrypt_keys_file.py --file=<file-path> --password=<wallet-password>
   ```

# Decrypt wallet cache file
The wallet cache file encrypts and stores transactions data related to imcoming, outgoing.

(The code can be decrypted for wallets that do not have an unconfirmed transaction and do not use subaddress, multisignature and unlock_time.)

## Features
decrypt_wallet_file.py extracts transactions data from &lt;walletname&gt; file.

The output data is as:

Type, Timestamp, BlockHeight, TX ID, TX Key, Amount, Fee, Change, Destination Address

## Use instructions
1. py-cryptonight install
   - Run cmd in the py-cryptonite folder
   ```
    python setup.py install
   ```
2. Run decrypt_cache_file.py
   ```
   python decrypt_cache_file.py --file=<file-path> --password=<wallet-password>
   ```

## Deserialization of wallet file format
### Top-level root fields of wallet cache file
| Field Name | Size(bytes) | Description |
| ---------- | ----------- | ----------- |
| MAGIC FIELD(”monero wallet cache”) | 20 | Magic string ”monero wallet cache” |
| VERSION FIELD(2) | 1 | Cache version (currently 2) |
| m_blockchain | variable | Blockchain hash list |
| m_transfers | variable | List of outputs owned |
| m_account_public_address | 64 | Public spend/view key |
| m_key_images | variable | Key image map |
| m_unconfirmed_txs | variable | Unconfirmed outgoing transaction map |
| m_payments | variable | Confirmed incoming transaction map |
| m_tx_keys | variable | Outgoing transaction key map |
| m_confirmed_txs | variable | Confirmed outcoming transaction map |
| m_tx_notes | variable | Transaction description map |
| m_unconfirmed_payments | variable | Unconfirmed incoming transaction map |
| m_pub_keys | variable | Public key map |
| m_address_book | variable | Address book map |
| m_scanned_pool_txs[0] | variable | Scanned mempool transaction |
| m_scanned_pool_txs[1] | variable | Scanned mempool transaction |
| m_subaddresses | variable | Subaddress index list(major index, minor index) |
| m_subaddress_labels | variable | Subaddress label map |
|m_additional_tx_keys | variable | Additional transaction key |
| m_attributes | variable | Wallet attributes |
| m_account_tags | variable | Account labels |
| m_ring_history_saved | variable | Ring signature history |
| m_last_block_reward | 8 | Last mining reward |
| m_tx_device | variable | Hardware wallet transaction data |
| m_device_last_key_image_sync | 8 | Hardware wallet last key image synchronization time |
| m_cold_key_images | variable | Cold wallet key image map |
| m_has_ever_refreshed_from_node | 1 | Node synchronization status |
| m_background_sync_data | variable | Background synchronization data |

### Incoming transaction-related sub-fields in m_payments
| Field Name | Size(bytes) | Description |
| ---------- | ----------- | ----------- |
| m_tx_hash | 32 | Transaction hash(tx id) |
| m_amount | varint(1-10) | Received amount(in piconero) |
| m_fee | varint(1-10) | Transaction fee|
| m_block_height | varint(1-10) | Block height |
| m_timestamp | varint(1-10) | Block creation timestamp |

### Outgoing transaction-related sub-fields in m_confirmed_txs and m_dests
#### m_confirmed_txs
| Field Name | Size(bytes) | Description |
| ---------- | ----------- | ----------- |
| m_tx | variable | Transaction header |
| m_amount_in | varint(1-10) | Before sending amount |
| m_amount_out | varint(1-10) | Amount after subtracting fee(m_amount_in - fee) |
| m_change | varint(1-10) | Change |
| m_block_height | varint(1-10) | Block height |
| m_dests | variable | Destination address etc. |
| m_timestamp | varint(1-10) | Block creation timestamp |

#### m_dests
| Field Name | Size(bytes) | Description |
| ---------- | ----------- | ----------- |
| original | variable | Destination address |
| amount | varint(1-10) | Sending amount(in piconero) |
| addr | 64 | Recipient public key | 
| is_subaddress | bool | Subaddress status(General address: 0x00, Subaddress: 0x01) |
| is_integrated | bool | Integrated address status(General address: 0x00, Integrated address: 0x01) |

## Tx_id sample list
The resulting transaction IDs from running the dataset are as follows, and you can use them to view the transaction details on the Monero Explorer.

1. bb957ca1aa4a548fcb09f1ba70abc5cc90a4f85d15922bb13d40bab96cb66c6b
2. ad49c70b4e05b9f956a99523068ab9b08229168befe0e2091c97dd83489b3a39
3. ee0f5701dafee5649eeadc4f2c1a7eaa85cdb73828010d5c3ff313882a987bb3
4. af7934453a430895b2a5b6d8cbcbf683c13893e8650f01f80304ccc3a391b9c2
5. f799a90e7c8518ef60aac07846064c40c8dc6d80f024f1e4d61758cf8883cba3

# Notice: Modified Third-Party Code
This repository includes code adapted from the py-cryptonight project.
Original repository: https://github.com/ph4r05/py-cryptonight
