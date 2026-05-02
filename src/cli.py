from __future__ import annotations

import argparse

from src.a51 import A51Cipher
from src.attack import (
    evaluate_attack_success_rates,
    recover_keys_reduced_keyspace,
    sweep_known_plaintext_lengths,
)
from src.demo import run_guided_demo


def _parse_int(value: str) -> int:
    return int(value, 0)


def _cmd_keystream(args: argparse.Namespace) -> int:
    cipher = A51Cipher(args.key, args.frame)
    bits = cipher.keystream_bits(args.bits)
    print("".join(str(b) for b in bits))
    return 0


def _cmd_encrypt(args: argparse.Namespace) -> int:
    cipher = A51Cipher(args.key, args.frame)
    plaintext = bytes.fromhex(args.hex_data)
    ciphertext = cipher.encrypt(plaintext)
    print(ciphertext.hex())
    return 0


def _cmd_decrypt(args: argparse.Namespace) -> int:
    cipher = A51Cipher(args.key, args.frame)
    ciphertext = bytes.fromhex(args.hex_data)
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext.hex())
    return 0


def _cmd_attack(args: argparse.Namespace) -> int:
    known_plaintext = bytes.fromhex(args.known_plaintext_hex)
    ciphertext = bytes.fromhex(args.ciphertext_hex)
    result = recover_keys_reduced_keyspace(
        known_plaintext=known_plaintext,
        ciphertext=ciphertext,
        frame_number=args.frame,
        known_key_prefix=args.known_key_prefix,
        unknown_bits=args.unknown_bits,
        max_candidates=args.max_candidates,
    )
    print(f"tried_keys={result.tried_keys}")
    print(f"known_keystream_bytes={result.known_keystream_bytes}")
    print(f"elapsed_seconds={result.elapsed_seconds:.6f}")
    if result.candidates:
        print("candidates=" + ",".join(hex(k) for k in result.candidates))
    else:
        print("candidates=")
    return 0


def _cmd_attack_sweep(args: argparse.Namespace) -> int:
    lengths = [int(part.strip()) for part in args.lengths.split(",") if part.strip()]
    plaintext = bytes.fromhex(args.plaintext_hex)
    points = sweep_known_plaintext_lengths(
        real_key=args.real_key,
        frame_number=args.frame,
        known_key_prefix=args.known_key_prefix,
        unknown_bits=args.unknown_bits,
        plaintext=plaintext,
        lengths=lengths,
    )
    print("length_bytes,candidate_count,success,unique_recovery,elapsed_seconds")
    for p in points:
        print(
            f"{p.length_bytes},{p.candidate_count},{int(p.success)},"
            f"{int(p.unique_recovery)},{p.elapsed_seconds:.6f}"
        )
    return 0


def _cmd_attack_rate(args: argparse.Namespace) -> int:
    lengths = [int(part.strip()) for part in args.lengths.split(",") if part.strip()]
    points = evaluate_attack_success_rates(
        frame_number=args.frame,
        unknown_bits=args.unknown_bits,
        lengths=lengths,
        trials=args.trials,
        seed=args.seed,
    )
    print(
        "length_bytes,trials,success_rate,unique_recovery_rate,"
        "avg_candidate_count,avg_elapsed_seconds"
    )
    for p in points:
        print(
            f"{p.length_bytes},{p.trials},{p.success_rate:.4f},"
            f"{p.unique_recovery_rate:.4f},{p.avg_candidate_count:.4f},"
            f"{p.avg_elapsed_seconds:.6f}"
        )
    return 0


def _fmt_bits(value: int, width: int) -> str:
    return format(value, f"0{width}b")


def _cmd_demo(args: argparse.Namespace) -> int:
    result = run_guided_demo(
        message=args.message,
        real_key=args.key,
        frame_number=args.frame,
        unknown_bits=args.unknown_bits,
    )

    print("=== GSM A5/1 Guided Demo ===")
    print(f"Message: {result.plaintext.decode('utf-8')}")
    print(f"Frame number: {hex(result.frame_number)}")
    print()
    print("Step 1: LFSR states after key+frame init (pre-keystream)")
    print(f"R1 (19b): {_fmt_bits(result.initial_r1, 19)}")
    print(f"R2 (22b): {_fmt_bits(result.initial_r2, 22)}")
    print(f"R3 (23b): {_fmt_bits(result.initial_r3, 23)}")
    print()
    print("Step 2: Generated keystream")
    print(result.keystream.hex())
    print()
    print("Step 3: Ciphertext (hex)")
    print(result.ciphertext.hex())
    print()
    print("Step 4: Known-plaintext attack (reduced keyspace)")
    print(f"known_key_prefix={hex(result.known_key_prefix)}")
    print(f"unknown_bits={result.unknown_bits}")
    print(f"recovered_key={hex(result.recovered_key)}")
    print(f"attack_elapsed_seconds={result.attack_elapsed_seconds:.6f}")
    print()
    print("Step 5: Decrypted message")
    print(result.decrypted.decode('utf-8'))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="A5/1 educational stream cipher CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    ks = sub.add_parser("keystream", help="Generate keystream bits")
    ks.add_argument("--key", required=True, type=_parse_int, help="64-bit key (e.g. 0x1234)")
    ks.add_argument("--frame", required=True, type=_parse_int, help="22-bit frame number")
    ks.add_argument("--bits", required=True, type=int, help="Number of bits")
    ks.set_defaults(func=_cmd_keystream)

    enc = sub.add_parser("encrypt", help="Encrypt hex plaintext")
    enc.add_argument("--key", required=True, type=_parse_int, help="64-bit key")
    enc.add_argument("--frame", required=True, type=_parse_int, help="22-bit frame number")
    enc.add_argument("--hex-data", required=True, help="Plaintext as hex bytes")
    enc.set_defaults(func=_cmd_encrypt)

    dec = sub.add_parser("decrypt", help="Decrypt hex ciphertext")
    dec.add_argument("--key", required=True, type=_parse_int, help="64-bit key")
    dec.add_argument("--frame", required=True, type=_parse_int, help="22-bit frame number")
    dec.add_argument("--hex-data", required=True, help="Ciphertext as hex bytes")
    dec.set_defaults(func=_cmd_decrypt)

    atk = sub.add_parser("attack", help="Run reduced-keyspace known-plaintext attack simulator")
    atk.add_argument("--frame", required=True, type=_parse_int, help="22-bit frame number")
    atk.add_argument("--known-key-prefix", required=True, type=_parse_int, help="Known high bits of key")
    atk.add_argument("--unknown-bits", required=True, type=int, help="Unknown lower key bits to brute-force")
    atk.add_argument("--known-plaintext-hex", required=True, help="Known plaintext as hex bytes")
    atk.add_argument("--ciphertext-hex", required=True, help="Ciphertext segment as hex bytes")
    atk.add_argument("--max-candidates", type=int, default=10, help="Stop after this many candidates")
    atk.set_defaults(func=_cmd_attack)

    sweep = sub.add_parser("attack-sweep", help="Measure attack success vs known plaintext length")
    sweep.add_argument("--real-key", required=True, type=_parse_int, help="Actual 64-bit key used to generate ciphertext")
    sweep.add_argument("--frame", required=True, type=_parse_int, help="22-bit frame number")
    sweep.add_argument("--known-key-prefix", required=True, type=_parse_int, help="Known high bits of key")
    sweep.add_argument("--unknown-bits", required=True, type=int, help="Unknown lower key bits to brute-force")
    sweep.add_argument("--plaintext-hex", required=True, help="Full plaintext sample as hex")
    sweep.add_argument("--lengths", required=True, help="Comma-separated byte lengths, e.g. 1,2,4,8")
    sweep.set_defaults(func=_cmd_attack_sweep)

    rate = sub.add_parser("attack-rate", help="Estimate success rates across randomized trials")
    rate.add_argument("--frame", required=True, type=_parse_int, help="22-bit frame number")
    rate.add_argument("--unknown-bits", required=True, type=int, help="Unknown lower key bits to brute-force")
    rate.add_argument("--lengths", required=True, help="Comma-separated byte lengths, e.g. 1,2,4,8")
    rate.add_argument("--trials", type=int, default=20, help="Number of randomized trials")
    rate.add_argument("--seed", type=_parse_int, default=0, help="PRNG seed for reproducibility")
    rate.set_defaults(func=_cmd_attack_rate)

    demo = sub.add_parser("demo", help="Run one end-to-end guided terminal demo")
    demo.add_argument("--message", default="GSM-A51-DEMO-BLOCK", help="Demo plaintext message")
    demo.add_argument("--key", type=_parse_int, default=0x123456789ABCDEF0, help="64-bit demo key")
    demo.add_argument("--frame", type=_parse_int, default=0x13456, help="22-bit frame number")
    demo.add_argument("--unknown-bits", type=int, default=12, help="Unknown key bits for attack simulation")
    demo.set_defaults(func=_cmd_demo)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
