import hashlib
import struct

def sha256d(b):
    """Podwójne SHA256 (SHA256d)"""
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def little_endian(hex_str):
    """Konwersja hex string do little endian"""
    return bytes.fromhex(''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)])))

def encode_varint(i):
    """Kodowanie liczby jako Bitcoin varint"""
    if i < 0xfd:
        return bytes([i])
    elif i <= 0xffff:
        return b'\xfd' + struct.pack('<H', i)
    elif i <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', i)
    else:
        return b'\xff' + struct.pack('<Q', i)

def parse_der_signature(sig_hex):
    """
    Parsuje DER-encoded sygnaturę.
    Usuwamy ostatni bajt (sighash type) – jeżeli sygnatura ma dodatkowy bajt push opcode, zostanie on pominięty.
    """
    sig_bytes = bytes.fromhex(sig_hex)
    # Jeśli pierwszy bajt to 0x30, to mamy format bez dodatkowego bajtu push opcode.
    if sig_bytes[0] == 0x30:
        der = sig_bytes[:-1]  # usuń ostatni bajt (sighash type)
    else:
        der = sig_bytes[1:-1]  # usuń push opcode oraz ostatni bajt
    if der[0] != 0x30:
        raise ValueError("Niepoprawny DER: brak 0x30 na początku")
    if der[2] != 0x02:
        raise ValueError("Niepoprawny DER: brak 0x02 przed r")
    len_r = der[3]
    r_start = 4
    r_end = r_start + len_r
    r_bytes = der[r_start:r_end]
    if der[r_end] != 0x02:
        raise ValueError("Niepoprawny DER: brak 0x02 przed s")
    len_s = der[r_end+1]
    s_start = r_end + 2
    s_end = s_start + len_s
    r_hex = r_bytes.hex()
    s_hex = der[s_start:s_end].hex()
    return r_hex, s_hex

# -------------------------
# Podana transakcja (JSON)
tx = {
  "txid": "ef208ac60a0c138c09f3b8248329cf3650de938f26da8092f7131f6e931aae2d",
  "size": 191,
  "version": 1,
  "locktime": 0,
  "fee": 194,
  "inputs": [
    {
      "coinbase": False,
      "txid": "05c47d203c4fdd3f910d7e4d43e73f6041b9ed30b280f5966c8a28983acba42e",
      "output": 240,
      "sigscript": "47304402201b3d4513fced8a3c0ba6888f5becf661fc820c24ecc1d9f922d46f8881b17e7302200e2a39910e9a3b2e54ed19bf2e25f7e04eadabcc0b6e5523c5e91775eefc445e012103c76cd381f5db43f5135e37d679fe67b10827ea7377ab17994dcd8fe37f4f94db",
      "sequence": 4294967295,
      "pkscript": "76a914c62794ae79ffbe6cdca5f192457aff20e785214e88ac",
      "value": 794,
      "address": "1K4kD71yTSX7bo7SA6qBQoMUsS6R87jZbH",
      "witness": []
    }
  ],
  "outputs": [
    {
      "address": "1K4Wkhd6Y7rJW86UfWoe1PtHwZfEaNjZbH",
      "pkscript": "76a914c61c595343704c7e3518fe2afdf0bed7f251abb988ac",
      "value": 600,
      "spent": False,
      "spender": None
    }
  ],
  "block": {
    "height": 881012,
    "position": 2393
  },
  "deleted": False,
  "time": 1737956787,
  "rbf": False,
  "weight": 764
}

# -------------------------
# Stałe dla transakcji:
version_hex = struct.pack("<I", tx["version"]).hex()
locktime_hex = struct.pack("<I", tx["locktime"]).hex()
sighash_hex = struct.pack("<I", 1).hex()  # SIGHASH_ALL = 1
input_count_hex = encode_varint(len(tx["inputs"])).hex()

def build_output(output):
    value_hex = struct.pack("<Q", output["value"]).hex()
    script = output["pkscript"]
    script_len_hex = encode_varint(len(bytes.fromhex(script))).hex()
    return value_hex + script_len_hex + script

outputs_hex = "".join(build_output(o) for o in tx["outputs"])
output_count_hex = encode_varint(len(tx["outputs"])).hex()

def build_preimage_for_input(i):
    inputs_hex = ""
    for idx, inp in enumerate(tx["inputs"]):
        prev_txid_le = little_endian(inp["txid"]).hex()
        vout_hex = struct.pack("<I", inp["output"]).hex()
        if idx == i:
            script = inp["pkscript"]
            script_len_hex = encode_varint(len(bytes.fromhex(script))).hex()
        else:
            script = ""
            script_len_hex = encode_varint(0).hex()
        sequence_hex = struct.pack("<I", inp["sequence"]).hex()
        inputs_hex += prev_txid_le + vout_hex + script_len_hex + script + sequence_hex
    preimage_hex = version_hex + input_count_hex + inputs_hex + output_count_hex + outputs_hex + locktime_hex + sighash_hex
    return bytes.fromhex(preimage_hex)

# -------------------------
# Przetwarzamy input, którego adres to "1K4kD71yTSX7bo7SA6qBQoMUsS6R87jZbH"
for i, inp in enumerate(tx["inputs"]):
    if inp.get("address") != "1K4kD71yTSX7bo7SA6qBQoMUsS6R87jZbH":
        continue  # przetwarzamy tylko odpowiedni input

    # Dla transakcji legacy korzystamy z sigscript
    sigscript = inp["sigscript"]
    if sigscript:
        try:
            r_hex, s_hex = parse_der_signature(sigscript)
        except Exception as e:
            r_hex, s_hex = "Błąd", "Błąd"
    elif inp.get("witness") and len(inp["witness"]) > 0:
        witness_sig = inp["witness"][0]
        try:
            r_hex, s_hex = parse_der_signature(witness_sig)
        except Exception as e:
            r_hex, s_hex = "Błąd", "Błąd"
    else:
        r_hex, s_hex = "Brak", "Brak"

    preimage = build_preimage_for_input(i)
    z_hash = sha256d(preimage)

    # Dla transakcji legacy nie ma klucza publicznego w witness – klucz publiczny jest częścią sigscript,
    # ale standardowo nie wyodrębniamy go bezpośrednio z DER sygnatury.
    pubkey = None

    print(f"Input {i} (adres: {inp.get('address')}):")
    print("  r =", r_hex)
    print("  s =", s_hex)
    print("  z (hash, little endian) =", z_hash.hex())
    print("  z (hash, big endian)   =", z_hash[::-1].hex())
    if pubkey:
        print("  Klucz publiczny =", pubkey)
    else:
        print("  Klucz publiczny: brak")
    print("-" * 60)
