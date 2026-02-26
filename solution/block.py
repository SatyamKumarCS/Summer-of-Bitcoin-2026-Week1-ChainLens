# Block parser for Bitcoin Core blk/rev/xor files

import hashlib
import sys
import os
import struct
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.reader import BufferReader
from src.parser import parse_transaction, parse_transaction_bytes, double_sha256
from src.script import classify_output
from src.analysis import compute_fees
from src.undo import parse_undo_data
from src.utils.varint import read_bitcoin_core_varint, decompress_amount


BLOCK_MAGIC = b'\xf9\xbe\xb4\xd9'  # mainnet


def xor_decode(data: bytes, key: bytes) -> bytes:
    if not key or all(b == 0 for b in key):
        return data
    key_len = len(key)
    # extend key to match data length, then XOR in one shot
    full_key = (key * (len(data) // key_len + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, full_key))


def compute_merkle_root(txid_hashes: list) -> bytes:
    if not txid_hashes:
        return b'\x00' * 32
    hashes = list(txid_hashes)
    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        new_hashes = []
        for i in range(0, len(hashes), 2):
            new_hashes.append(double_sha256(hashes[i] + hashes[i + 1]))
        hashes = new_hashes
    return hashes[0]


def parse_block_header(reader: BufferReader) -> dict:
    header_start = reader.cursor
    version = reader.read_int32()
    prev_block = reader.read_hash()
    merkle_root = reader.read_hash()
    timestamp = reader.read_uint32()
    bits = reader.read_uint32()
    nonce = reader.read_uint32()
    header_bytes = reader.data[header_start:reader.cursor]
    block_hash_bytes = double_sha256(header_bytes)
    return {
        "version": version,
        "prev_block_hash": prev_block[::-1].hex(),
        "merkle_root": merkle_root[::-1].hex(),
        "merkle_root_bytes": merkle_root,
        "timestamp": timestamp,
        "bits": format(bits, '08x'),
        "nonce": nonce,
        "block_hash": block_hash_bytes[::-1].hex(),
    }


def skip_transaction(reader: BufferReader) -> int:
    """Skip over a transaction, return its start offset."""
    start = reader.cursor
    reader.read(4)  # version
    saved = reader.cursor
    marker = reader.read_uint8()
    flag = reader.read_uint8()
    is_segwit = (marker == 0x00 and flag == 0x01)
    if not is_segwit:
        reader.cursor = saved
    num_inputs = reader.read_compact_size()
    for _ in range(num_inputs):
        reader.read(36)  # txid + vout
        sl = reader.read_compact_size()
        reader.read(sl + 4)  # scriptsig + sequence
    num_outputs = reader.read_compact_size()
    for _ in range(num_outputs):
        reader.read(8)  # value
        sl = reader.read_compact_size()
        reader.read(sl)  # scriptpubkey
    if is_segwit:
        for _ in range(num_inputs):
            ni = reader.read_compact_size()
            for _ in range(ni):
                il = reader.read_compact_size()
                reader.read(il)
    reader.read(4)  # locktime
    return start


def parse_tx_fast(raw: bytes):
    """Block-mode parser: only extracts txid, version, weight, outputs, num_inputs, coinbase script."""
    n = len(raw)
    pos = 4  # skip version
    version = struct.unpack_from('<i', raw, 0)[0]

    # segwit check
    is_segwit = (raw[pos] == 0x00 and raw[pos+1] == 0x01)
    if is_segwit:
        pos += 2

    inputs_start = pos

    # read number of inputs
    num_inputs, pos = _read_cs(raw, pos)

    # for coinbase we need the first script_sig
    coinbase_script_sig = None
    for i in range(num_inputs):
        pos += 36  # skip txid + vout
        sl, pos = _read_cs(raw, pos)
        if i == 0:
            coinbase_script_sig = raw[pos:pos+sl]
        pos += sl + 4  # skip script + sequence

    # outputs
    num_outputs, pos = _read_cs(raw, pos)
    output_values = []
    output_scripts = []
    for _ in range(num_outputs):
        val = struct.unpack_from('<Q', raw, pos)[0]
        pos += 8
        sl, pos = _read_cs(raw, pos)
        output_values.append(val)
        output_scripts.append(raw[pos:pos+sl])
        pos += sl

    outputs_end = pos

    # skip witness
    if is_segwit:
        for _ in range(num_inputs):
            ni, pos = _read_cs(raw, pos)
            for _ in range(ni):
                il, pos = _read_cs(raw, pos)
                pos += il

    # txid
    if is_segwit:
        nw = raw[:4] + raw[inputs_start:outputs_end] + raw[-4:]
        txid_bytes = double_sha256(nw)
        non_witness_size = len(nw)
    else:
        txid_bytes = double_sha256(raw)
        non_witness_size = n

    witness_size = n - non_witness_size
    weight = non_witness_size * 4 + witness_size
    vbytes = (weight + 3) // 4

    return {
        "txid_bytes": txid_bytes,
        "txid": txid_bytes[::-1].hex(),
        "version": version,
        "weight": weight,
        "vbytes": vbytes,
        "num_inputs": num_inputs,
        "output_values": output_values,
        "output_scripts": output_scripts,
        "coinbase_script_sig": coinbase_script_sig,
    }


def _read_cs(data, pos):
    """Read CompactSize from bytes at pos, return (value, new_pos)."""
    b = data[pos]
    if b < 0xFD:
        return b, pos + 1
    elif b == 0xFD:
        return struct.unpack_from('<H', data, pos + 1)[0], pos + 3
    elif b == 0xFE:
        return struct.unpack_from('<I', data, pos + 1)[0], pos + 5
    else:
        return struct.unpack_from('<Q', data, pos + 1)[0], pos + 9


def _decode_bip34_height(script_sig: bytes) -> int:
    if not script_sig:
        return 0
    height_len = script_sig[0]
    if height_len == 0 or height_len > 8:
        return 0
    if height_len > len(script_sig) - 1:
        height_len = len(script_sig) - 1
    return int.from_bytes(script_sig[1:1 + height_len], 'little')


def _pre_parse_rev_blocks(rev_data: bytes) -> list:
    rev_blocks = []
    reader = BufferReader(rev_data)
    while reader.has_more() and reader.remaining() >= 8:
        magic = reader.read_bytes(4)
        if magic != BLOCK_MAGIC:
            break
        rev_size = reader.read_uint32()
        data_start = reader.cursor
        num_txundo = reader.read_compact_size()
        reader.cursor = data_start
        raw_data = reader.read_bytes(rev_size)
        if reader.remaining() >= 32:
            reader.read_bytes(32)  # checksum
        rev_blocks.append((num_txundo, raw_data))
    return rev_blocks


def _match_rev_blocks(blk_blocks_info: list, rev_blocks: list) -> list:
    """Match rev blocks to blk blocks by tx count."""
    from collections import defaultdict
    rev_by_count = defaultdict(list)
    for idx, (count, data) in enumerate(rev_blocks):
        rev_by_count[count].append(idx)

    matched = [None] * len(blk_blocks_info)
    used = set()

    for blk_idx, num_txs in enumerate(blk_blocks_info):
        non_cb = num_txs - 1
        candidates = rev_by_count.get(non_cb, [])
        for rev_idx in candidates:
            if rev_idx not in used:
                matched[blk_idx] = rev_blocks[rev_idx][1]
                used.add(rev_idx)
                break
        if matched[blk_idx] is None and non_cb > 0:
            raise ValueError(f"No matching rev block for blk block {blk_idx} with {non_cb} non-coinbase txs")

    return matched


def parse_block_file(blk_path: str, rev_path: str, xor_path: str) -> list:
    """Main entry: parse a blk*.dat with its rev and xor files."""
    with open(xor_path, 'rb') as f:
        xor_key = f.read()
    with open(blk_path, 'rb') as f:
        blk_data = xor_decode(f.read(), xor_key)
    with open(rev_path, 'rb') as f:
        rev_data = xor_decode(f.read(), xor_key)

    # pass 1: enumerate blocks and find tx byte ranges
    blk_reader = BufferReader(blk_data)
    block_infos = []  # (data_start, block_size, num_txs, [(tx_start, tx_end), ...])

    while blk_reader.has_more() and blk_reader.remaining() >= 8:
        magic = blk_reader.read_bytes(4)
        if magic != BLOCK_MAGIC:
            break
        block_size = blk_reader.read_uint32()
        data_start = blk_reader.cursor
        blk_reader.read_bytes(80)  # header
        num_txs = blk_reader.read_compact_size()
        tx_ranges = []
        for _ in range(num_txs):
            tx_start = skip_transaction(blk_reader)
            tx_ranges.append((tx_start, blk_reader.cursor))
        block_infos.append((data_start, block_size, num_txs, tx_ranges))
        blk_reader.cursor = data_start + block_size

    # pass 2: parse rev blocks
    rev_blocks = _pre_parse_rev_blocks(rev_data)

    # pass 3: match rev to blk
    blk_tx_counts = [info[2] for info in block_infos]
    matched_rev = _match_rev_blocks(blk_tx_counts, rev_blocks)

    # pass 4: process each block
    os.makedirs("out", exist_ok=True)
    results = []

    for blk_idx, (data_start, block_size, num_txs, tx_ranges) in enumerate(block_infos):
        # Parse header
        reader = BufferReader(blk_data)
        reader.cursor = data_start
        header = parse_block_header(reader)

        # Parse undo data
        if matched_rev[blk_idx] is not None and num_txs > 1:
            rev_reader = BufferReader(matched_rev[blk_idx])
            undo_prevouts = parse_undo_data(rev_reader, num_txs)
        else:
            undo_prevouts = []

        # analyze each tx
        analyzed_txs = []
        coinbase_info = None
        total_fees = 0
        total_weight = 0
        script_type_counts = {}
        txid_hashes = []

        for tx_idx in range(num_txs):
            tx_start, tx_end = tx_ranges[tx_idx]
            raw_bytes = blk_data[tx_start:tx_end]
            tx = parse_tx_fast(raw_bytes)
            txid_hashes.append(tx["txid_bytes"])
            is_coinbase = (tx_idx == 0)

            # classify outputs and sum values
            total_output_sats = sum(tx["output_values"])
            out_types = [classify_output(s.hex()) for s in tx["output_scripts"]]

            if is_coinbase:
                bip34_height = _decode_bip34_height(tx["coinbase_script_sig"])
                coinbase_info = {
                    "bip34_height": bip34_height,
                    "coinbase_script_hex": tx["coinbase_script_sig"].hex(),
                    "total_output_sats": total_output_sats,
                }
                fee_sats = 0
            else:
                undo_idx = tx_idx - 1
                prevouts = undo_prevouts[undo_idx]
                total_input_sats = sum(p["value_sats"] for p in prevouts)
                fee_sats = total_input_sats - total_output_sats
                total_fees += fee_sats

            total_weight += tx["weight"]
            for st in out_types:
                script_type_counts[st] = script_type_counts.get(st, 0) + 1

            analyzed_txs.append({
                "txid": tx["txid"],
                "version": tx["version"],
                "vin": [{}] * tx["num_inputs"],
                "vout": [{"script_type": st} for st in out_types],
                "fee_sats": fee_sats,
                "weight": tx["weight"],
                "vbytes": tx["vbytes"],
            })

        # merkle root check
        computed_merkle = compute_merkle_root(txid_hashes)
        merkle_valid = (computed_merkle == header["merkle_root_bytes"])

        total_vbytes = sum(t["vbytes"] for t in analyzed_txs[1:]) if num_txs > 1 else 0
        avg_fee_rate = round(total_fees / total_vbytes, 1) if total_vbytes > 0 else 0.0

        clean_header = {k: v for k, v in header.items() if k != "merkle_root_bytes"}
        clean_header["merkle_root_valid"] = merkle_valid

        block_result = {
            "ok": True, "mode": "block",
            "block_header": clean_header,
            "tx_count": num_txs,
            "coinbase": coinbase_info,
            "transactions": analyzed_txs,
            "block_stats": {
                "total_fees_sats": total_fees,
                "total_weight": total_weight,
                "avg_fee_rate_sat_vb": avg_fee_rate,
                "script_type_summary": script_type_counts,
            },
        }

        # write immediately to free memory
        block_hash = clean_header["block_hash"]
        out_path = os.path.join("out", f"{block_hash}.json")
        with open(out_path, 'w') as f:
            json.dump(block_result, f, separators=(',', ':'))

        results.append({"block_hash": block_hash, "tx_count": num_txs})
        # free memory for large block files
        del analyzed_txs, block_result

    return results
