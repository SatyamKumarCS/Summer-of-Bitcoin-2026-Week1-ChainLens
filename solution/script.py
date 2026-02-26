# Script classification, disassembly, and OP_RETURN decoding

import struct

# full opcode table (ref: https://en.bitcoin.it/wiki/Script)

OPCODE_NAMES = {
    0x00: "OP_0",
    0x4c: "OP_PUSHDATA1",
    0x4d: "OP_PUSHDATA2",
    0x4e: "OP_PUSHDATA4",
    0x4f: "OP_1NEGATE",
    0x50: "OP_RESERVED",
    0x51: "OP_1", 0x52: "OP_2", 0x53: "OP_3", 0x54: "OP_4",
    0x55: "OP_5", 0x56: "OP_6", 0x57: "OP_7", 0x58: "OP_8",
    0x59: "OP_9", 0x5a: "OP_10", 0x5b: "OP_11", 0x5c: "OP_12",
    0x5d: "OP_13", 0x5e: "OP_14", 0x5f: "OP_15", 0x60: "OP_16",
    0x61: "OP_NOP",
    0x62: "OP_VER",
    0x63: "OP_IF",
    0x64: "OP_NOTIF",
    0x65: "OP_VERIF",
    0x66: "OP_VERNOTIF",
    0x67: "OP_ELSE",
    0x68: "OP_ENDIF",
    0x69: "OP_VERIFY",
    0x6a: "OP_RETURN",
    0x6b: "OP_TOALTSTACK",
    0x6c: "OP_FROMALTSTACK",
    0x6d: "OP_2DROP",
    0x6e: "OP_2DUP",
    0x6f: "OP_3DUP",
    0x70: "OP_2OVER",
    0x71: "OP_2ROT",
    0x72: "OP_2SWAP",
    0x73: "OP_IFDUP",
    0x74: "OP_DEPTH",
    0x75: "OP_DROP",
    0x76: "OP_DUP",
    0x77: "OP_NIP",
    0x78: "OP_OVER",
    0x79: "OP_PICK",
    0x7a: "OP_ROLL",
    0x7b: "OP_ROT",
    0x7c: "OP_SWAP",
    0x7d: "OP_TUCK",
    0x7e: "OP_CAT",
    0x7f: "OP_SUBSTR",
    0x80: "OP_LEFT",
    0x81: "OP_RIGHT",
    0x82: "OP_SIZE",
    0x83: "OP_INVERT",
    0x84: "OP_AND",
    0x85: "OP_OR",
    0x86: "OP_XOR",
    0x87: "OP_EQUAL",
    0x88: "OP_EQUALVERIFY",
    0x89: "OP_RESERVED1",
    0x8a: "OP_RESERVED2",
    0x8b: "OP_1ADD",
    0x8c: "OP_1SUB",
    0x8d: "OP_2MUL",
    0x8e: "OP_2DIV",
    0x8f: "OP_NEGATE",
    0x90: "OP_ABS",
    0x91: "OP_NOT",
    0x92: "OP_0NOTEQUAL",
    0x93: "OP_ADD",
    0x94: "OP_SUB",
    0x95: "OP_MUL",
    0x96: "OP_DIV",
    0x97: "OP_MOD",
    0x98: "OP_LSHIFT",
    0x99: "OP_RSHIFT",
    0x9a: "OP_BOOLAND",
    0x9b: "OP_BOOLOR",
    0x9c: "OP_NUMEQUAL",
    0x9d: "OP_NUMEQUALVERIFY",
    0x9e: "OP_NUMNOTEQUAL",
    0x9f: "OP_LESSTHAN",
    0xa0: "OP_GREATERTHAN",
    0xa1: "OP_LESSTHANOREQUAL",
    0xa2: "OP_GREATERTHANOREQUAL",
    0xa3: "OP_MIN",
    0xa4: "OP_MAX",
    0xa5: "OP_WITHIN",
    0xa6: "OP_RIPEMD160",
    0xa7: "OP_SHA1",
    0xa8: "OP_SHA256",
    0xa9: "OP_HASH160",
    0xaa: "OP_HASH256",
    0xab: "OP_CODESEPARATOR",
    0xac: "OP_CHECKSIG",
    0xad: "OP_CHECKSIGVERIFY",
    0xae: "OP_CHECKMULTISIG",
    0xaf: "OP_CHECKMULTISIGVERIFY",
    0xb0: "OP_NOP1",
    0xb1: "OP_CHECKLOCKTIMEVERIFY",
    0xb2: "OP_CHECKSEQUENCEVERIFY",
    0xb3: "OP_NOP4",
    0xb4: "OP_NOP5",
    0xb5: "OP_NOP6",
    0xb6: "OP_NOP7",
    0xb7: "OP_NOP8",
    0xb8: "OP_NOP9",
    0xb9: "OP_NOP10",
    0xba: "OP_CHECKSIGADD",
}


def disassemble(script_hex: str) -> str:
    """Turn script hex into OP_CODE asm string."""
    if not script_hex:
        return ""

    script = bytes.fromhex(script_hex)
    tokens = []
    i = 0

    while i < len(script):
        opcode = script[i]
        i += 1

        # direct push (1-75 bytes)
        if 0x01 <= opcode <= 0x4b:
            data = script[i:i + opcode]
            tokens.append(f"OP_PUSHBYTES_{opcode} {data.hex()}")
            i += opcode


        elif opcode == 0x4c:
            if i >= len(script):
                break
            length = script[i]
            i += 1
            data = script[i:i + length]
            tokens.append(f"OP_PUSHDATA1 {data.hex()}")
            i += length


        elif opcode == 0x4d:
            if i + 1 >= len(script):
                break
            length = struct.unpack('<H', script[i:i + 2])[0]
            i += 2
            data = script[i:i + length]
            tokens.append(f"OP_PUSHDATA2 {data.hex()}")
            i += length


        elif opcode == 0x4e:
            if i + 3 >= len(script):
                break
            length = struct.unpack('<I', script[i:i + 4])[0]
            i += 4
            data = script[i:i + length]
            tokens.append(f"OP_PUSHDATA4 {data.hex()}")
            i += length


        elif opcode in OPCODE_NAMES:
            tokens.append(OPCODE_NAMES[opcode])


        else:
            tokens.append(f"OP_UNKNOWN_{opcode:#04x}")

    return " ".join(tokens)


def classify_output(script_hex: str) -> str:
    """Figure out what type of output this scriptPubKey is."""
    script = bytes.fromhex(script_hex)
    slen = len(script)

    # p2pkh: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    if slen == 25 and script[0] == 0x76 and script[1] == 0xa9 and script[2] == 0x14 and script[23] == 0x88 and script[24] == 0xac:
        return "p2pkh"

    # p2sh
    if slen == 23 and script[0] == 0xa9 and script[1] == 0x14 and script[22] == 0x87:
        return "p2sh"

    # p2wpkh
    if slen == 22 and script[0] == 0x00 and script[1] == 0x14:
        return "p2wpkh"

    # p2wsh
    if slen == 34 and script[0] == 0x00 and script[1] == 0x20:
        return "p2wsh"

    # p2tr (taproot)
    if slen == 34 and script[0] == 0x51 and script[1] == 0x20:
        return "p2tr"

    # op_return
    if slen >= 1 and script[0] == 0x6a:
        return "op_return"

    return "unknown"


def classify_input(vin_entry: dict) -> str:
    """Classify how this input is being spent."""
    prevout_hex = vin_entry.get("prevout", {}).get("script_pubkey_hex", "")
    script_sig_hex = vin_entry.get("script_sig_hex", "")
    witness = vin_entry.get("witness", [])

    if not prevout_hex:
        return "unknown"

    prevout_type = classify_output(prevout_hex)

    if prevout_type == "p2pkh":
        return "p2pkh"

    if prevout_type == "p2wpkh":
        return "p2wpkh"

    if prevout_type == "p2wsh":
        return "p2wsh"

    if prevout_type == "p2tr":
        # keypath vs scriptpath detection
        if len(witness) == 1:
            item_len = len(witness[0]) // 2  # hex string length / 2
            if item_len == 64 or item_len == 65:
                return "p2tr_keypath"
        # scriptpath: >= 2 items, last starts with 0xc0/0xc1 (control block)
        if len(witness) >= 2:
            last = witness[-1]
            if len(last) >= 2:
                first_byte = int(last[0:2], 16)
                if (first_byte & 0xFE) == 0xC0:
                    return "p2tr_scriptpath"
        # fallback
        if len(witness) == 1:
            return "p2tr_keypath"
        return "p2tr_keypath"

    if prevout_type == "p2sh":
        # nested segwit check
        if script_sig_hex and witness:
            # extract redeem script from scriptSig
            sig_bytes = bytes.fromhex(script_sig_hex)

            if len(sig_bytes) >= 1:
                push_len = sig_bytes[0]
                if 0x01 <= push_len <= 0x4b and push_len + 1 == len(sig_bytes):
                    redeem_script = sig_bytes[1:]

                    if len(redeem_script) == 22 and redeem_script[0] == 0x00 and redeem_script[1] == 0x14:
                        return "p2sh-p2wpkh"

                    if len(redeem_script) == 34 and redeem_script[0] == 0x00 and redeem_script[1] == 0x20:
                        return "p2sh-p2wsh"
        return "unknown"

    return "unknown"


def decode_op_return(script_hex: str) -> tuple:
    """Decode OP_RETURN payload. Returns (data_hex, data_utf8, protocol)."""
    script = bytes.fromhex(script_hex)
    if len(script) == 0 or script[0] != 0x6a:
        return ("", None, "unknown")

    # collect all pushes after OP_RETURN
    i = 1
    data_parts = []

    while i < len(script):
        opcode = script[i]
        i += 1

        # direct push
        if 0x01 <= opcode <= 0x4b:
            data = script[i:i + opcode]
            data_parts.append(data)
            i += opcode


        elif opcode == 0x4c:
            if i >= len(script):
                break
            length = script[i]
            i += 1
            data = script[i:i + length]
            data_parts.append(data)
            i += length


        elif opcode == 0x4d:
            if i + 1 >= len(script):
                break
            length = struct.unpack('<H', script[i:i + 2])[0]
            i += 2
            data = script[i:i + length]
            data_parts.append(data)
            i += length


        elif opcode == 0x4e:
            if i + 3 >= len(script):
                break
            length = struct.unpack('<I', script[i:i + 4])[0]
            i += 4
            data = script[i:i + length]
            data_parts.append(data)
            i += length

        # OP_0 = empty push
        elif opcode == 0x00:
            data_parts.append(b'')

        else:
            # not a push opcode, stop here
            break

    combined = b''.join(data_parts)
    data_hex = combined.hex()

    # try utf-8
    try:
        data_utf8 = combined.decode('utf-8')
    except (UnicodeDecodeError, ValueError):
        data_utf8 = None

    # known protocol prefixes
    if data_hex.startswith("6f6d6e69"):
        protocol = "omni"
    elif data_hex.startswith("0109f91102"):
        protocol = "opentimestamps"
    else:
        protocol = "unknown"

    return (data_hex, data_utf8, protocol)
