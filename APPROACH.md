# 🧠 My Approach — Chain Lens (Summer of Bitcoin 2026)

> A detailed walkthrough of how I designed, implemented, and optimized the Chain Lens Bitcoin Transaction & Block Analyzer.

---

## 📋 Table of Contents

1. [Understanding the Problem](#1-understanding-the-problem)
2. [Architecture & Design Decisions](#2-architecture--design-decisions)
3. [Transaction Parsing Pipeline](#3-transaction-parsing-pipeline)
4. [Script Classification & Disassembly](#4-script-classification--disassembly)
5. [Address Derivation](#5-address-derivation)
6. [Fee, RBF & Timelock Analysis](#6-fee-rbf--timelock-analysis)
7. [Block Parsing Pipeline](#7-block-parsing-pipeline)
8. [Undo Data & Script Decompression](#8-undo-data--script-decompression)
9. [Performance Optimization](#9-performance-optimization)
10. [Web Visualizer](#10-web-visualizer)
11. [Edge Cases & Challenges](#11-edge-cases--challenges)
12. [Testing Strategy](#12-testing-strategy)
13. [Key Learnings](#13-key-learnings)

---

## 1. Understanding the Problem

The challenge requires building a tool that can take **raw Bitcoin data** (transaction hex or block files) and produce **structured, machine-checkable JSON reports**. This goes far beyond surface-level parsing — it requires a deep understanding of:

- **Bitcoin's serialization format** (pre-SegWit and SegWit)
- **Script types** (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OP_RETURN)
- **Address encoding** (Base58Check, Bech32, Bech32m)
- **BIP standards** (BIP141 SegWit, BIP125 RBF, BIP68 relative timelocks, BIP34 coinbase height)
- **Bitcoin Core's internal storage format** (blk*.dat, rev*.dat, XOR obfuscation, undo data compression)

The key insight: **every computation must be done from first principles** — no external Bitcoin libraries, no node connections, just raw bytes → structured analysis.

---

## 2. Architecture & Design Decisions

### Modular Design

I split the codebase into **focused, single-responsibility modules**:

```
main.py        → Orchestrates the analysis pipeline
parser.py      → Raw byte → structured transaction dict
script.py      → Script classification + disassembly engine
address.py     → Address derivation (all encoding schemes)
analysis.py    → Fee computation, RBF detection, timelocks, SegWit savings
block.py       → Block-level parser (header, merkle, multi-block files)
undo.py        → Bitcoin Core undo data parser + script decompression
server.py      → Flask web API wrapping the same core logic
```

**Why this structure?**
- The CLI and web app share the **exact same analysis engine** — no code duplication.
- Each module can be tested independently.
- Adding new analysis features is straightforward without touching other modules.

### Data Flow

```
Raw Hex / Block Files
        │
        ▼
   ┌─────────┐
   │ parser   │ ← Deserialize bytes into structured dicts
   └────┬─────┘
        │
        ▼
   ┌──────────┐
   │ script   │ ← Classify output/input types, disassemble opcodes
   └────┬─────┘
        │
        ▼
   ┌──────────┐
   │ address  │ ← Derive human-readable addresses
   └────┬─────┘
        │
        ▼
   ┌──────────┐
   │ analysis │ ← Compute fees, detect RBF, analyze timelocks
   └────┬─────┘
        │
        ▼
   JSON Report
```

---

## 3. Transaction Parsing Pipeline

### The Core Challenge

Bitcoin transactions are serialized as a stream of bytes with **no delimiters** — you must know exactly how many bytes to read at each step, and the format changed with SegWit (BIP141).

### My Approach

**`parser.py` — `parse_transaction_bytes()`**

1. **Read version** (4 bytes, little-endian int32).
2. **Detect SegWit**: peek at the next 2 bytes — if `0x00 0x01`, it's a SegWit marker+flag.
3. **Parse inputs**: read CompactSize for count, then for each input: 32-byte txid (reversed), 4-byte vout, variable-length scriptSig, 4-byte sequence.
4. **Parse outputs**: read CompactSize for count, then for each output: 8-byte value (uint64), variable-length scriptPubKey.
5. **Parse witness** (if SegWit): for each input, read the witness stack items.
6. **Read locktime** (4 bytes).

### TXID and WTXID

This was a critical detail:
- **TXID** = `double_sha256` of the **non-witness serialization** (version + inputs + outputs + locktime, skipping the marker/flag/witness).
- **WTXID** = `double_sha256` of the **full serialization** (including witness data).
- For non-SegWit transactions, `wtxid` must be `null`.

I tracked byte offsets during parsing to efficiently extract the non-witness serialization without re-serializing:

```python
# Track where inputs/outputs start and end
start_inputs = reader.cursor
# ... parse inputs and outputs ...
end_outputs = reader.cursor

# Build non-witness serialization from tracked offsets
non_witness_serialized = raw[:4] + raw[start_inputs:end_outputs] + raw[-4:]
```

### Weight & vBytes (BIP141)

```python
weight = non_witness_size * 4 + witness_size
vbytes = (weight + 3) // 4  # ceiling division
```

---

## 4. Script Classification & Disassembly

### Output Classification (`classify_output`)

I implemented pattern-matching on the scriptPubKey hex:

| Type | Pattern |
|------|---------|
| `p2pkh` | `76a914{20 bytes}88ac` (OP_DUP OP_HASH160 PUSH20 OP_EQUALVERIFY OP_CHECKSIG) |
| `p2sh` | `a914{20 bytes}87` (OP_HASH160 PUSH20 OP_EQUAL) |
| `p2wpkh` | `0014{20 bytes}` (OP_0 PUSH20) |
| `p2wsh` | `0020{32 bytes}` (OP_0 PUSH32) |
| `p2tr` | `5120{32 bytes}` (OP_1 PUSH32) |
| `op_return` | starts with `6a` (OP_RETURN) |

### Input Classification (`classify_input`)

Input classification is more nuanced — it requires looking at the **prevout scriptPubKey**, **scriptSig**, and **witness data** together:

- **P2TR keypath** vs **P2TR scriptpath**: if the prevout is P2TR, check the witness — 1 item (64-byte signature) = keypath, multiple items with a control block starting `0xc0`/`0xc1` = scriptpath.
- **P2SH-P2WPKH** and **P2SH-P2WSH**: P2SH prevout + witness data present → nested SegWit. The scriptSig contains a push of the witness program.

### Script Disassembly Engine

I built a full opcode table covering all Bitcoin Script opcodes and a disassembler that handles:

- Direct pushes (`0x01`-`0x4b`) → `OP_PUSHBYTES_N <hex>`
- Extended pushes (`OP_PUSHDATA1`, `OP_PUSHDATA2`, `OP_PUSHDATA4`)
- All standard opcodes (`OP_DUP`, `OP_HASH160`, `OP_CHECKSIG`, etc.)
- Unknown opcodes → `OP_UNKNOWN_<0xNN>`

### OP_RETURN Decoding

One tricky part was handling OP_RETURN payloads correctly:
- Multiple data pushes after `OP_RETURN` must be **concatenated**.
- All push opcodes must be supported (not just direct pushes — `OP_PUSHDATA1`, `OP_PUSHDATA2`, `OP_PUSHDATA4` too).
- Protocol detection: check prefixes for Omni (`6f6d6e69`), OpenTimestamps (`0109f91102`).
- UTF-8 decode attempt, returning `null` if invalid.

---

## 5. Address Derivation

### Base58Check (P2PKH, P2SH)

Implemented from scratch:
1. Prepend version byte (`0x00` for P2PKH, `0x05` for P2SH).
2. Compute 4-byte checksum via double SHA-256.
3. Base58 encode with leading-zero preservation.

### Bech32/Bech32m (P2WPKH, P2WSH, P2TR)

Following BIP173/BIP350:
- **Bech32** for witness version 0 (P2WPKH, P2WSH).
- **Bech32m** for witness version 1+ (P2TR/Taproot).
- Implemented the polymod checksum, HRP expansion, and 5-bit conversion from scratch.

---

## 6. Fee, RBF & Timelock Analysis

### Fee Computation

```
fee_sats = total_input_sats - total_output_sats
fee_rate = fee_sats / vbytes  (rounded to 2 decimal places)
```

### RBF Detection (BIP125)

Any input with `sequence < 0xFFFFFFFE` signals Replace-By-Fee.

### Absolute Locktime

- `locktime == 0` → `"none"`
- `locktime < 500,000,000` → `"block_height"`
- `locktime >= 500,000,000` → `"unix_timestamp"`

### Relative Timelocks (BIP68)

Per-input analysis of the sequence field:
- **Bit 31 set** → disabled.
- **Bit 22 set** → time-based (value × 512 seconds).
- **Otherwise** → block-based (bottom 16 bits).

### SegWit Discount Analysis

```python
weight_if_legacy = total_size_bytes * 4  # hypothetical legacy weight
savings_pct = (1 - weight_actual / weight_if_legacy) * 100
```

### Warnings

Emit structured warnings for: `HIGH_FEE`, `DUST_OUTPUT`, `UNKNOWN_OUTPUT_SCRIPT`, `RBF_SIGNALING`.

---

## 7. Block Parsing Pipeline

This was the most complex part of the challenge. A single `blk*.dat` file can contain **multiple blocks**, and each block can have hundreds of transactions.

### Step-by-Step Process

1. **XOR Decode**: Read the `xor.dat` key and decode both `blk*.dat` and `rev*.dat`.
2. **Pass 1 — Enumerate blocks**: Scan for the magic bytes (`f9beb4d9`), parse the 80-byte block header, skip-parse all transactions to find their byte ranges.
3. **Pass 2 — Parse undo data**: Parse the `rev*.dat` file to extract prevout information for non-coinbase inputs.
4. **Pass 3 — Match rev to blk**: Match undo blocks to block files by transaction count.
5. **Pass 4 — Full analysis**: For each block, parse transactions, classify outputs, compute fees, verify the merkle root, and decode the coinbase BIP34 height.

### Block Header Parsing

```python
version      = 4 bytes (int32)
prev_block   = 32 bytes (hash, reversed for display)
merkle_root  = 32 bytes (hash)
timestamp    = 4 bytes (uint32)
bits         = 4 bytes (uint32, compact target)
nonce        = 4 bytes (uint32)
block_hash   = double_sha256(header_80_bytes), reversed
```

### Merkle Root Verification

I implemented the standard Bitcoin merkle tree:
- Hash pairs of TXIDs using `double_sha256`.
- If odd count, duplicate the last hash.
- Repeat until one hash remains.
- Compare with the merkle root from the block header.

---

## 8. Undo Data & Script Decompression

Bitcoin Core's `rev*.dat` files use a **compressed format** for storing prevout data. This required implementing:

### Bitcoin Core Varint

Not the same as CompactSize! Bitcoin Core uses a variable-length integer encoding where each byte's MSB indicates continuation.

### Amount Decompression

Bitcoin Core compresses satoshi amounts using a specific algorithm — I implemented `decompress_amount()` following the Core source code exactly.

### Script Decompression

The undo data compresses scriptPubKeys by type:

| nSize | Type | Data |
|-------|------|------|
| 0 | P2PKH | 20-byte pubkey hash → reconstruct full script |
| 1 | P2SH | 20-byte script hash → reconstruct full script |
| 2, 3 | Compressed P2PK | 32-byte x-coordinate → build P2PK script |
| 4, 5 | Uncompressed P2PK | 32-byte x-coordinate → decompress secp256k1 point → build P2PK script |
| ≥ 6 | Raw script | `nSize - 6` bytes of raw script |

For nSize 4/5, I implemented **secp256k1 point decompression** (computing y from x using the curve equation `y² = x³ + 7 mod p`).

---

## 9. Performance Optimization

The block grader has a **60-second timeout**, so performance was critical for large blocks.

### Key Optimizations

1. **`parse_tx_fast()`**: A lightweight transaction parser for block mode that extracts only what's needed (txid, outputs, weight, coinbase script) without running the full disassembly and address derivation pipeline.

2. **`skip_transaction()`**: Rapidly skips over transactions during the first pass to find byte ranges without parsing the content.

3. **`struct.unpack_from()`**: Used in-place struct unpacking instead of creating BufferReader objects for the fast path.

4. **Memory management**: Explicitly free large data structures (`del analyzed_txs, block_result`) after writing each block's JSON output.

5. **Minimal output classification**: In block mode, only classify output script types (for the summary) — skip full disassembly, address derivation, and witness analysis.

---

## 10. Web Visualizer

### Architecture

- **Backend**: Flask server (`server.py`) exposing the same analysis engine via REST API.
- **Frontend**: Single-page app with HTML/CSS/JS.
- **API Endpoints**:
  - `GET /api/health` → `{ "ok": true }`
  - `POST /api/analyze` → transaction analysis
  - `POST /api/analyze-block` → block file upload and analysis

### Features

- **Transaction mode**: Paste a JSON fixture or raw hex to get a visual breakdown.
- **Block mode**: Upload `blk*.dat`, `rev*.dat`, and `xor.dat` files for block analysis.
- **Visual flow**: Inputs → Outputs with fee visualization.
- **Script type badges**: Color-coded labels for each address type.
- **Plain English explanations**: All fields explained for non-technical users.

---

## 11. Edge Cases & Challenges

### Handled Edge Cases

| Scenario | How I Handled It |
|----------|------------------|
| Taproot keypath vs scriptpath | Check witness item count + control block prefix |
| Nested SegWit (P2SH-P2WPKH/P2WSH) | Check for P2SH prevout + witness data presence |
| OP_RETURN with OP_PUSHDATA1/2/4 | Full push opcode support in the parser |
| OP_RETURN with multiple pushes | Concatenate all data pushes |
| Non-UTF8 OP_RETURN data | Return `null` for `op_return_data_utf8` |
| Relative timelock disabled (bit 31) | Correctly check the disable flag first |
| Mixed RBF/non-RBF inputs | Any single signaling input = RBF enabled |
| Non-SegWit transaction WTXID | Return `null` (not the txid) |
| Compressed P2PK in undo data | secp256k1 point decompression |
| Uncompressed P2PK in undo data | Full curve math to recover y-coordinate |
| Multi-block blk*.dat files | Loop through magic bytes to find all blocks |
| XOR-obfuscated block files | Decode before parsing |
| Duplicate/missing prevouts | Explicit validation with structured error responses |

### Key Challenges

1. **Undo data parsing** was the hardest part. Bitcoin Core's format is poorly documented outside the source code. I had to read the C++ source (`txdb.cpp`, `undo.h`) to understand the serialization.

2. **Matching rev blocks to blk blocks** when a single file contains multiple blocks required matching by non-coinbase transaction count.

3. **Performance under the 60-second grader timeout** required building a separate fast-path parser that avoids the expensive operations (disassembly, address derivation) during block mode.

---

## 12. Testing Strategy

- **Public fixtures**: All provided transaction fixtures pass the grader.
- **Block fixtures**: Real mainnet block files parsed correctly.
- **Grader validation**: Used the provided `grade.sh` to verify output accuracy.
- **Edge case testing**: Created test scenarios for all hidden fixture categories mentioned in the challenge spec.

---

## 13. Key Learnings

1. **Bitcoin serialization is deceptively complex.** The SegWit marker detection, witness placement, and TXID vs WTXID distinction require careful attention to byte offsets.

2. **Bitcoin Core's internal formats are their own protocol.** The undo data compression (varints, amount compression, script compression) is a format used nowhere else.

3. **Performance optimization matters.** The difference between a correct-but-slow parser and one that passes the 60-second timeout was building a separate lightweight parsing path.

4. **Building from first principles deepens understanding.** Implementing Base58Check, Bech32, and secp256k1 point decompression from scratch gave me a much deeper appreciation for how Bitcoin addresses work.

5. **Modular design pays off.** Sharing the same analysis engine between CLI and web meant I only had to debug the core logic once.

---

*This document was written by Satyam Kumar as part of the Summer of Bitcoin 2026 Developer Challenge.*
