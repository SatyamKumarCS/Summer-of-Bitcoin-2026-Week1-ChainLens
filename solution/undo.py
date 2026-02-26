# Parse rev*.dat undo data (Bitcoin Core format)

import sys
import os
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.utils.reader import BufferReader
from src.utils.varint import read_bitcoin_core_varint, decompress_amount


def decompress_script(reader: BufferReader, n_size: int) -> str:
    """Decompress scriptPubKey from undo data based on nSize.
    0=P2PKH, 1=P2SH, 2/3=compressed P2PK, 4/5=uncompressed P2PK, >=6=raw script.
    """
    if n_size == 0:
        # p2pkh
        hash20 = reader.read_bytes(20)
        script = b'\x76\xa9\x14' + hash20 + b'\x88\xac'
        return script.hex()

    elif n_size == 1:
        # p2sh
        hash20 = reader.read_bytes(20)
        script = b'\xa9\x14' + hash20 + b'\x87'
        return script.hex()

    elif n_size in (2, 3):
        # compressed pubkey -> P2PK script
        key_data = reader.read_bytes(32)
        prefix = bytes([n_size])
        pubkey = prefix + key_data
        script = bytes([0x21]) + pubkey + bytes([0xac])
        return script.hex()

    elif n_size in (4, 5):
        # uncompressed pubkey (stored as 32 bytes, need to decompress)
        key_data = reader.read_bytes(32)
        # reconstruct compressed key first, then decompress to uncompressed
        prefix_byte = 0x02 if n_size == 4 else 0x03
        compressed = bytes([prefix_byte]) + key_data
        # decompress on secp256k1
        uncompressed = _decompress_pubkey(compressed)
        if uncompressed is None:
            script = bytes([0x21]) + compressed + bytes([0xac])
            return script.hex()
        script = bytes([0x41]) + uncompressed + bytes([0xac])
        return script.hex()

    else:
        # raw script
        script_len = n_size - 6
        script = reader.read_bytes(script_len)
        return script.hex()


def _decompress_pubkey(compressed: bytes) -> bytes | None:
    """secp256k1 point decompression."""
    if len(compressed) != 33:
        return None

    prefix = compressed[0]
    x = int.from_bytes(compressed[1:], 'big')

    # secp256k1: y^2 = x^3 + 7
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)

    if y_sq != pow(y, 2, p):
        return None

    # fix parity
    if prefix == 0x02:
        if y % 2 != 0:
            y = p - y
    elif prefix == 0x03:
        if y % 2 == 0:
            y = p - y
    else:
        return None

    return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


def parse_undo_data(reader: BufferReader, num_txs: int) -> list:
    """Parse undo data for a block. Returns list of prevout lists (one per non-coinbase tx)."""
    all_tx_prevouts = []


    num_tx_undos = reader.read_compact_size()

    for _ in range(num_tx_undos):
        # each CTxUndo has N coin entries
        num_inputs = reader.read_compact_size()

        tx_prevouts = []
        for _ in range(num_inputs):
            # nCode encodes height and coinbase flag
            code = read_bitcoin_core_varint(reader)
            height = code >> 1
            is_coinbase = bool(code & 1)

            # dummy version field for compat with old serialization
            if height > 0:
                _version_dummy = read_bitcoin_core_varint(reader)

            # compressed amount -> real sats
            compressed_amount = read_bitcoin_core_varint(reader)
            value_sats = decompress_amount(compressed_amount)

            # compressed script
            n_size = read_bitcoin_core_varint(reader)
            script_pubkey_hex = decompress_script(reader, n_size)

            tx_prevouts.append({
                "value_sats": value_sats,
                "script_pubkey_hex": script_pubkey_hex,
                "height": height,
                "coinbase": is_coinbase,
            })

        all_tx_prevouts.append(tx_prevouts)

    return all_tx_prevouts
