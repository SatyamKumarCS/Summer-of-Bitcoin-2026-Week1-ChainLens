# Deserialize raw Bitcoin transactions from hex into structured dicts

import hashlib
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.utils.reader import BufferReader


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def parse_transaction(raw_hex: str) -> dict:
    """Parse a raw tx hex into a dict with version, vin, vout, witness, etc."""
    return parse_transaction_bytes(bytes.fromhex(raw_hex))


def parse_transaction_bytes(raw: bytes) -> dict:
    """Parse raw tx bytes directly (faster path for block mode)."""
    reader = BufferReader(raw)

    version = reader.read_int32()

    # segwit marker check
    saved_cursor = reader.cursor
    marker = reader.read_uint8()
    flag = reader.read_uint8()

    is_segwit = (marker == 0x00 and flag == 0x01)
    if not is_segwit:
        reader.cursor = saved_cursor

    # track where inputs+outputs start for non-witness serialization
    start_inputs = reader.cursor

    # inputs
    num_inputs = reader.read_compact_size()
    vin = []
    for _ in range(num_inputs):
        txid_bytes = reader.read_hash()
        txid = txid_bytes[::-1].hex()
        vout = reader.read_uint32()
        script_sig_len = reader.read_compact_size()
        script_sig = reader.read_bytes(script_sig_len).hex()
        sequence = reader.read_uint32()
        vin.append({
            "txid": txid,
            "vout": vout,
            "script_sig_hex": script_sig,
            "sequence": sequence,
        })

    # outputs
    num_outputs = reader.read_compact_size()
    vout = []
    for i in range(num_outputs):
        value = reader.read_uint64()
        script_len = reader.read_compact_size()
        script_pubkey = reader.read_bytes(script_len).hex()
        vout.append({
            "n": i,
            "value_sats": value,
            "script_pubkey_hex": script_pubkey,
        })

    end_outputs = reader.cursor

    # witness (if segwit)
    witness_data = []
    if is_segwit:
        for _ in range(num_inputs):
            num_items = reader.read_compact_size()
            items = []
            for _ in range(num_items):
                item_len = reader.read_compact_size()
                item = reader.read_bytes(item_len).hex()
                items.append(item)
            witness_data.append(items)
    else:
        witness_data = [[] for _ in range(num_inputs)]

    locktime = reader.read_uint32()

    # txid = double_sha256 of non-witness serialization, reversed
    if is_segwit:
        # build non-witness serialization from tracked offsets (no re-parse)
        non_witness_serialized = raw[:4] + raw[start_inputs:end_outputs] + raw[-4:]
        txid_hash = double_sha256(non_witness_serialized)
        txid = txid_hash[::-1].hex()

        wtxid_hash = double_sha256(raw)
        wtxid = wtxid_hash[::-1].hex()
    else:
        txid_hash = double_sha256(raw)
        txid = txid_hash[::-1].hex()
        wtxid = None

    # sizes / weight
    total_size = len(raw)

    if is_segwit:
        non_witness_size = len(non_witness_serialized)
        witness_size = total_size - non_witness_size
        weight = non_witness_size * 4 + witness_size
    else:
        non_witness_size = total_size
        witness_size = 0
        weight = total_size * 4

    vbytes = (weight + 3) // 4

    return {
        "version": version,
        "vin": vin,
        "vout": vout,
        "witness": witness_data,
        "locktime": locktime,
        "segwit": is_segwit,
        "txid": txid,
        "wtxid": wtxid,
        "size_bytes": total_size,
        "weight": weight,
        "vbytes": vbytes,
        "non_witness_size": non_witness_size,
        "witness_size": witness_size,
    }
