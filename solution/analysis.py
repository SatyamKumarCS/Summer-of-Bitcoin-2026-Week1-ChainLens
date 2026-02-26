# Fee computation, timelock/RBF analysis, warnings

import math


def compute_fees(total_input_sats: int, total_output_sats: int, vbytes: int) -> dict:
    fee_sats = total_input_sats - total_output_sats
    if vbytes > 0:
        fee_rate = round(fee_sats / vbytes, 2)
    else:
        fee_rate = 0.0
    return {
        "fee_sats": fee_sats,
        "fee_rate_sat_vb": fee_rate,
    }


def detect_rbf(vin: list) -> bool:
    """Any input with sequence < 0xFFFFFFFE signals RBF (BIP125)."""
    for inp in vin:
        if inp["sequence"] < 0xFFFFFFFE:
            return True
    return False


def classify_locktime(locktime: int) -> tuple:
    if locktime == 0:
        return ("none", 0)
    elif locktime < 500000000:
        return ("block_height", locktime)
    else:
        return ("unix_timestamp", locktime)


def analyze_relative_timelock(sequence: int) -> dict:
    """BIP68 relative timelock check for a single input."""
    SEQUENCE_LOCKTIME_DISABLE_FLAG = 0x80000000
    SEQUENCE_LOCKTIME_TYPE_FLAG = 0x00400000
    SEQUENCE_LOCKTIME_MASK = 0x0000FFFF

    if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
        return {"enabled": False}

    value = sequence & SEQUENCE_LOCKTIME_MASK

    if sequence & SEQUENCE_LOCKTIME_TYPE_FLAG:
        # time-based: each unit is 512 seconds
        return {
            "enabled": True,
            "type": "time",
            "value": value * 512,
        }
    else:
        # block-based
        return {
            "enabled": True,
            "type": "blocks",
            "value": value,
        }


def generate_warnings(fee_sats: int, fee_rate: float, vout: list, rbf: bool) -> list:
    warnings = []


    if fee_sats > 1000000 or fee_rate > 200:
        warnings.append({"code": "HIGH_FEE"})


    for output in vout:
        if output.get("script_type") != "op_return" and output.get("value_sats", 0) < 546:
            warnings.append({"code": "DUST_OUTPUT"})
            break


    for output in vout:
        if output.get("script_type") == "unknown":
            warnings.append({"code": "UNKNOWN_OUTPUT_SCRIPT"})
            break


    if rbf:
        warnings.append({"code": "RBF_SIGNALING"})

    return warnings


def compute_segwit_savings(is_segwit: bool, size_bytes: int, weight: int,
                           non_witness_size: int, witness_size: int) -> dict | None:
    if not is_segwit:
        return None

    weight_if_legacy = size_bytes * 4
    savings_pct = round((1 - weight / weight_if_legacy) * 100, 2) if weight_if_legacy > 0 else 0.0

    return {
        "witness_bytes": witness_size,
        "non_witness_bytes": non_witness_size,
        "total_bytes": size_bytes,
        "weight_actual": weight,
        "weight_if_legacy": weight_if_legacy,
        "savings_pct": savings_pct,
    }
