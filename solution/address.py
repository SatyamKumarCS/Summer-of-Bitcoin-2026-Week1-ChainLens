# Address derivation for Bitcoin mainnet (Base58Check + Bech32/Bech32m)

import hashlib


# --- base58check ---

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hash160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', _sha256(data)).digest()


def base58check_encode(payload: bytes) -> str:
    checksum = _sha256(_sha256(payload))[:4]
    data = payload + checksum

    n = int.from_bytes(data, 'big')
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(BASE58_ALPHABET[r])
    # leading zero bytes become '1's in base58
    for byte in data:
        if byte == 0:
            result.append(BASE58_ALPHABET[0])
        else:
            break
    return ''.join(reversed(result))


def p2pkh_address(pubkey_hash: bytes) -> str:
    return base58check_encode(b'\x00' + pubkey_hash)


def p2sh_address(script_hash: bytes) -> str:
    return base58check_encode(b'\x05' + script_hash)


# --- bech32 / bech32m ---
# ref: BIP173 / BIP350

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1
BECH32M_CONST = 0x2bc830a3


def _bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_create_checksum(hrp, data, spec):
    const = BECH32M_CONST if spec == "bech32m" else BECH32_CONST
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    spec = "bech32m" if witver > 0 else "bech32"
    data = [witver] + _convertbits(witprog, 8, 5)
    checksum = _bech32_create_checksum(hrp, data, spec)
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in data + checksum)




def derive_address(script_type: str, script_hex: str) -> str | None:
    """Derive mainnet address from the script type + hex."""
    script = bytes.fromhex(script_hex)

    if script_type == "p2pkh":
        # hash is at bytes 3..23
        pubkey_hash = script[3:23]
        return p2pkh_address(pubkey_hash)

    if script_type == "p2sh":

        script_hash = script[2:22]
        return p2sh_address(script_hash)

    if script_type == "p2wpkh":

        pubkey_hash = script[2:22]
        return bech32_encode("bc", 0, pubkey_hash)

    if script_type == "p2wsh":

        script_hash = script[2:34]
        return bech32_encode("bc", 0, script_hash)

    if script_type == "p2tr":

        pubkey = script[2:34]
        return bech32_encode("bc", 1, pubkey)

    return None
