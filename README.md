# ⛓️ Summer of Bitcoin 2026 — Chain Lens

> **Status:** ✅ Round 1 Cleared  
> **Challenge:** Week 1 — Chain Lens (Bitcoin Transaction & Block Analyzer)  
> **Candidate:** Satyam Kumar

---

## 🏆 About the Challenge

The Summer of Bitcoin 2026 Developer Challenge requires building a **CLI tool + web visualizer** that can:

1. **Parse raw Bitcoin transactions** from hex and produce a precise, machine-checkable JSON report.
2. **Parse raw Bitcoin Core block files** (`blk*.dat`, `rev*.dat`, `xor.dat`) and generate per-block analysis.
3. **Visualize transactions** through a web interface that explains Bitcoin to non-technical users.

This is a protocol-focused challenge — it tests deep understanding of Bitcoin transaction serialization, accounting, script classification, and address derivation.

---

## 📁 Project Structure

```
├── cli.sh                    # CLI entry point (transaction + block mode)
├── web.sh                    # Starts the Flask web visualizer
├── setup.sh                  # Installs dependencies
├── grade.sh                  # Runs the grader
├── demo.md                   # Demo video link
├── src/
│   ├── main.py               # CLI logic + transaction analyzer
│   ├── parser.py             # Raw transaction deserialization
│   ├── block.py              # Block-level parser (XOR, merkle, undo)
│   ├── script.py             # Script classification, disassembly, OP_RETURN
│   ├── analysis.py           # Fees, RBF, timelocks, SegWit savings
│   ├── address.py            # Base58Check + Bech32/Bech32m address derivation
│   ├── undo.py               # Undo data parser (rev*.dat) with script decompression
│   ├── server.py             # Flask web server with API endpoints
│   ├── templates/
│   │   └── index.html        # Web visualizer frontend
│   ├── static/
│   │   ├── app.js            # Frontend JavaScript
│   │   └── style.css         # Styling
│   └── utils/
│       ├── reader.py         # BufferReader for binary parsing
│       └── varint.py         # Bitcoin Core varint + amount decompression
├── fixtures/                 # Test fixtures (transactions + blocks)
├── grader/                   # Automated grader
└── out/                      # Generated JSON output files
```

---

## 🚀 How to Run

### Setup
```bash
./setup.sh
```

### CLI — Transaction Mode
```bash
./cli.sh fixtures/transactions/tx_legacy_p2pkh.json
```

### CLI — Block Mode
```bash
./cli.sh --block <blk*.dat> <rev*.dat> <xor.dat>
```

### Web Visualizer
```bash
./web.sh
# Open http://127.0.0.1:3000
```

---

## 🔗 Key Links

- **Challenge Repo:** [Summer of Bitcoin 2026 — Chain Lens](https://github.com/SummerOfBitcoin/2026-developer-challenge-1-chain-lens-SatyamKumarCS)
- **Approach Document:** [APPROACH.md](./APPROACH.md)

---

## 🐍 Solution Files

All Python source files are included in the [`solution/`](./solution/) directory:

| File | Description |
|------|-------------|
| `main.py` | CLI entry point + transaction analysis orchestrator |
| `parser.py` | Raw transaction deserialization (SegWit + Legacy) |
| `block.py` | Block-level parser (XOR decoding, merkle verification, multi-block) |
| `script.py` | Script classification, disassembly engine, OP_RETURN decoding |
| `analysis.py` | Fee computation, RBF detection, timelocks, SegWit savings |
| `address.py` | Address derivation (Base58Check, Bech32, Bech32m) |
| `undo.py` | Bitcoin Core undo data parser + script decompression |
| `server.py` | Flask web server with REST API |
| `utils/reader.py` | Cursor-based binary reader for Bitcoin wire format |
| `utils/varint.py` | Bitcoin Core varint encoding + amount decompression |

---

## 📌 Round 1 Results

✅ **All public transaction fixtures passed**  
✅ **Block parsing with real mainnet blocks passed**  
✅ **Web health check and API endpoints functional**  
✅ **Hidden fixture categories handled** (Taproot, SegWit, P2SH nesting, RBF, timelocks, OP_RETURN variants, undo data compression)

---

*Built with ❤️ for Summer of Bitcoin 2026*
