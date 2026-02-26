# CLI entry point for analyzing transactions and blocks

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.parser import parse_transaction
from src.script import classify_output, classify_input, disassemble, decode_op_return
from src.address import derive_address
from src.analysis import (
    compute_fees, detect_rbf, classify_locktime,
    analyze_relative_timelock, generate_warnings, compute_segwit_savings,
)


def error_response(code: str, message: str) -> dict:
    return {"ok": False, "error": {"code": code, "message": message}}


def analyze_transaction(raw_hex: str, prevouts_list: list, network: str = "mainnet") -> dict:
    # parse raw tx
    tx = parse_transaction(raw_hex)

    # build prevout lookup by (txid, vout)
    prevout_map = {}
    for p in prevouts_list:
        key = (p["txid"], p["vout"])
        if key in prevout_map:
            raise ValueError(f"Duplicate prevout: {key}")
        prevout_map[key] = p

    # match prevouts to inputs
    total_input_sats = 0
    for inp in tx["vin"]:
        key = (inp["txid"], inp["vout"])
        if key not in prevout_map:
            raise ValueError(f"Missing prevout for input: txid={inp['txid']}, vout={inp['vout']}")
        prevout = prevout_map[key]
        inp["prevout"] = {
            "value_sats": prevout["value_sats"],
            "script_pubkey_hex": prevout["script_pubkey_hex"],
        }
        total_input_sats += prevout["value_sats"]

    # make sure all prevouts are actually used
    used_keys = set((inp["txid"], inp["vout"]) for inp in tx["vin"])
    for key in prevout_map:
        if key not in used_keys:
            raise ValueError(f"Prevout does not correspond to any input: txid={key[0]}, vout={key[1]}")

    # classify outputs
    total_output_sats = 0
    vout_result = []
    for out in tx["vout"]:
        script_type = classify_output(out["script_pubkey_hex"])
        address = derive_address(script_type, out["script_pubkey_hex"])
        total_output_sats += out["value_sats"]

        entry = {
            "n": out["n"],
            "value_sats": out["value_sats"],
            "script_pubkey_hex": out["script_pubkey_hex"],
            "script_asm": disassemble(out["script_pubkey_hex"]),
            "script_type": script_type,
            "address": address,
        }

        if script_type == "op_return":
            data_hex, data_utf8, protocol = decode_op_return(out["script_pubkey_hex"])
            entry["op_return_data_hex"] = data_hex
            entry["op_return_data_utf8"] = data_utf8
            entry["op_return_protocol"] = protocol

        vout_result.append(entry)

    # classify inputs
    vin_result = []
    for i, inp in enumerate(tx["vin"]):
        inp["witness"] = tx["witness"][i]

        input_type = classify_input(inp)
        prevout_type = classify_output(inp["prevout"]["script_pubkey_hex"])
        address = derive_address(prevout_type, inp["prevout"]["script_pubkey_hex"])

        entry = {
            "txid": inp["txid"],
            "vout": inp["vout"],
            "sequence": inp["sequence"],
            "script_sig_hex": inp["script_sig_hex"],
            "script_asm": disassemble(inp["script_sig_hex"]),
            "witness": inp["witness"],
            "script_type": input_type,
            "address": address,
            "prevout": inp["prevout"],
            "relative_timelock": analyze_relative_timelock(inp["sequence"]),
        }

        # for segwit multisig, grab the witness script asm
        if input_type in ("p2wsh", "p2sh-p2wsh") and inp["witness"]:
            witness_script_hex = inp["witness"][-1]
            entry["witness_script_asm"] = disassemble(witness_script_hex)

        vin_result.append(entry)

    # fees
    fees = compute_fees(total_input_sats, total_output_sats, tx["vbytes"])

    # rbf
    rbf = detect_rbf(tx["vin"])

    # locktime
    locktime_type, locktime_value = classify_locktime(tx["locktime"])

    # warnings
    warnings = generate_warnings(fees["fee_sats"], fees["fee_rate_sat_vb"], vout_result, rbf)

    # segwit savings
    segwit_savings = compute_segwit_savings(
        tx["segwit"], tx["size_bytes"], tx["weight"],
        tx["non_witness_size"], tx["witness_size"],
    )

    result = {
        "ok": True,
        "network": network,
        "segwit": tx["segwit"],
        "txid": tx["txid"],
        "wtxid": tx["wtxid"],
        "version": tx["version"],
        "locktime": tx["locktime"],
        "size_bytes": tx["size_bytes"],
        "weight": tx["weight"],
        "vbytes": tx["vbytes"],
        "total_input_sats": total_input_sats,
        "total_output_sats": total_output_sats,
        "fee_sats": fees["fee_sats"],
        "fee_rate_sat_vb": fees["fee_rate_sat_vb"],
        "rbf_signaling": rbf,
        "locktime_type": locktime_type,
        "locktime_value": locktime_value,
        "segwit_savings": segwit_savings,
        "vin": vin_result,
        "vout": vout_result,
        "warnings": warnings,
    }

    return result


def handle_transaction_mode(fixture_path: str):
    try:
        with open(fixture_path, 'r') as f:
            fixture = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        result = error_response("INVALID_FIXTURE", str(e))
        print(json.dumps(result))
        sys.exit(1)

    network = fixture.get("network", "mainnet")
    raw_tx = fixture.get("raw_tx", "")
    prevouts = fixture.get("prevouts", [])

    if not raw_tx:
        result = error_response("INVALID_FIXTURE", "Missing raw_tx in fixture")
        print(json.dumps(result))
        sys.exit(1)

    try:
        result = analyze_transaction(raw_tx, prevouts, network)
    except Exception as e:
        result = error_response("INVALID_TX", str(e))
        print(json.dumps(result))
        sys.exit(1)

    # Write to out/<txid>.json
    os.makedirs("out", exist_ok=True)
    out_path = os.path.join("out", f"{result['txid']}.json")
    with open(out_path, 'w') as f:
        json.dump(result, f, indent=2)

    # also print to stdout
    print(json.dumps(result, indent=2))


def handle_block_mode(blk_path: str, rev_path: str, xor_path: str):
    from src.block import parse_block_file

    try:
        # writes JSON output files directly to out/
        results = parse_block_file(blk_path, rev_path, xor_path)
    except Exception as e:
        result = error_response("BLOCK_PARSE_ERROR", str(e))
        print(json.dumps(result), file=sys.stderr)
        sys.exit(1)


def main():
    args = sys.argv[1:]

    if not args:
        result = error_response("INVALID_ARGS", "No arguments provided")
        print(json.dumps(result))
        sys.exit(1)

    if args[0] == "--block":
        if len(args) < 4:
            result = error_response("INVALID_ARGS", "Block mode requires: --block <blk.dat> <rev.dat> <xor.dat>")
            print(json.dumps(result))
            sys.exit(1)
        handle_block_mode(args[1], args[2], args[3])
    else:
        handle_transaction_mode(args[0])


if __name__ == "__main__":
    main()
