# GSM A5/1 Stream Cipher Implementation

Educational implementation of the GSM A5/1 stream cipher with a CLI.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 -m src.cli keystream --key 0x123456789abcdef0 --frame 0x13456 --bits 64
python3 -m src.cli encrypt --key 0x123456789abcdef0 --frame 0x13456 --hex-data 00112233
python3 -m src.cli decrypt --key 0x123456789abcdef0 --frame 0x13456 --hex-data deadbeef
python3 -m src.cli attack --frame 0x13456 --known-key-prefix 0x123456789abcd --unknown-bits 12 --known-plaintext-hex 47534d2d4135312d44454d4f2d424c4f434b --ciphertext-hex <put-captured-ciphertext-hex>
python3 -m src.cli attack-sweep --real-key 0x123456789abcdef0 --frame 0x13456 --known-key-prefix 0x123456789abcd --unknown-bits 12 --plaintext-hex 47534d2d4135312d44454d4f2d424c4f434b --lengths 1,2,4,8,18
python3 -m src.cli attack-rate --frame 0x13456 --unknown-bits 12 --lengths 1,2,4,8,18 --trials 20 --seed 7
python3 -m src.cli demo
```

### Known-plaintext attack simulator

The `attack` command is an educational reduced-keyspace simulator:
- It derives keystream from known plaintext and ciphertext.
- It brute-forces only the lower `unknown-bits` of the 64-bit key while assuming the upper bits are known.
- It reports candidate keys, explored key count, and runtime.

Use `attack-sweep` to generate a compact table showing how candidate count drops as known plaintext length increases.

Use `attack-rate` to estimate success and unique-recovery percentages over multiple randomized, reproducible trials.

Use `demo` for a full step-by-step presentation flow in one command (LFSR states -> keystream -> ciphertext -> attack -> decrypted message).

## Reproducible live demo scenario

Use this exact scenario for a deterministic presentation demo:

- Real key: `0x123456789ABCDEF0`
- Frame: `0x13456`
- Unknown bits: `12`
- Known key prefix: `0x123456789abcd`
- Known plaintext (ASCII): `GSM-A51-DEMO-BLOCK`
- Known plaintext (hex): `47534d2d4135312d44454d4f2d424c4f434b`

Generate ciphertext:

```bash
python3 -m src.cli encrypt --key 0x123456789abcdef0 --frame 0x13456 --hex-data 47534d2d4135312d44454d4f2d424c4f434b
```

Run attack:

```bash
python3 -m src.cli attack --frame 0x13456 --known-key-prefix 0x123456789abcd --unknown-bits 12 --known-plaintext-hex 47534d2d4135312d44454d4f2d424c4f434b --ciphertext-hex <ciphertext-from-command-above>
```

## Tests

```bash
pytest -q
```
