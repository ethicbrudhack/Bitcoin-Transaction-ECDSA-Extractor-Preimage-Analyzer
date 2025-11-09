# 🧩 Bitcoin Transaction ECDSA Extractor & Preimage Analyzer

This Python script decodes and analyzes **Bitcoin legacy transactions** to extract key cryptographic components used in **ECDSA signatures** — including:

- `r` and `s` values from the DER-encoded signature  
- The message hash `z` (the double SHA256 of the transaction preimage)  
- Transaction preimage construction according to Bitcoin's **SIGHASH_ALL** rules  
- Optional public key extraction (if available)

---

## 🧠 Purpose

This tool is meant for **cryptography researchers, blockchain analysts, and Bitcoin developers** who want to:

- Understand how ECDSA signatures are embedded inside Bitcoin transactions  
- Reconstruct preimage data and verify `z = SHA256d(preimage)`  
- Extract `r`, `s`, and `z` for key recovery or validation experiments  
- Learn the internal structure of Bitcoin’s **legacy signature hashing process**

---

## ⚙️ How It Works

1. **Reads a transaction (JSON)** — simulating on-chain transaction data.  
2. **Parses the DER-encoded signature** from `sigscript` or `witness`:
   - Extracts `r` and `s` components.
3. **Builds the preimage** used in the ECDSA signing process:
   - Serializes inputs, outputs, version, and locktime.
   - Adds `SIGHASH_ALL` (value `1`).
4. **Computes `z`**, the double SHA256 hash (`SHA256d`) of the preimage.
5. **Displays**:
   - `r`, `s`
   - `z` in both **little-endian** and **big-endian** order
   - Public key (if available in the transaction input)

---

## 🧩 Core Components Explained

| Function | Description |
|-----------|--------------|
| `sha256d(b)` | Computes **double SHA256** — `SHA256(SHA256(b))` |
| `little_endian(hex_str)` | Converts a hex string into **little-endian byte order** |
| `encode_varint(i)` | Encodes integers into Bitcoin’s **VarInt format** |
| `parse_der_signature(sig_hex)` | Parses a **DER-encoded ECDSA signature** and extracts `r` and `s` |
| `build_preimage_for_input(i)` | Constructs the **preimage** for input `i` used to compute the signature hash |
| `sha256d(preimage)` | Produces the **message digest `z`** used in signing |

---

## 🧮 Example Output

Input 0 (adres: 1K4kD71yTSX7bo7SA6qBQoMUsS6R87jZbH):
r = 1b3d4513fced8a3c0ba6888f5becf661fc820c24ecc1d9f922d46f8881b17e73
s = 0e2a39910e9a3b2e54ed19bf2e25f7e04eadabcc0b6e5523c5e91775eefc445e
z (hash, little endian) = e9ff0a3ac01b5b94c0af97c83b48f4ed8d8f423a38c9d26b5031b8b95cf14e76
z (hash, big endian) = 764ef15cb9b831506bd2c9383a428f8dedf4483bc897afc0945b1bc03a0affe9
Klucz publiczny: brak

---

## 🧠 What You’ll Learn

✅ How Bitcoin serializes transactions for signing  
✅ How ECDSA signatures (`r`, `s`) are encoded in DER format  
✅ How to reconstruct the **exact hash `z`** that was signed  
✅ The difference between **little-endian** and **big-endian** in Bitcoin  
✅ How to parse raw transaction scripts into readable cryptographic components  

---

## 📜 Educational Use Cases

- Bitcoin transaction forensics  
- Key recovery and signature validation (research use)  
- Deep understanding of Bitcoin’s transaction signing algorithm  
- Educational cryptography demonstrations  

---

## 🚀 Usage

1. Save the script as `btc_signature_extractor.py`
2. Modify the `tx` dictionary with your own transaction JSON (from a block explorer)
3. Run:
   ```bash
   python3 btc_signature_extractor.py


Review the extracted:

r, s (signature values)

z (message hash)

transaction preimage structure

🧰 Dependencies

Python ≥ 3.8

No external libraries required (uses hashlib and struct only)

⚠️ Security & Ethical Notice

⚠️ This tool is for educational and research purposes only.
Do not use it to extract or analyze signatures from other people's transactions or private data.
It is meant for understanding Bitcoin’s cryptographic design, not for exploitation.

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
