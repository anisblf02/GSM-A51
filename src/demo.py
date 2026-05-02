from __future__ import annotations

from dataclasses import dataclass

from src.a51 import A51Cipher
from src.attack import recover_keys_reduced_keyspace


@dataclass
class GuidedDemoResult:
    plaintext: bytes
    ciphertext: bytes
    keystream: bytes
    frame_number: int
    real_key: int
    unknown_bits: int
    known_key_prefix: int
    initial_r1: int
    initial_r2: int
    initial_r3: int
    recovered_key: int
    decrypted: bytes
    attack_elapsed_seconds: float


def run_guided_demo(message: str, real_key: int, frame_number: int, unknown_bits: int) -> GuidedDemoResult:
    if not message:
        raise ValueError("message cannot be empty")
    if unknown_bits < 1 or unknown_bits > 24:
        raise ValueError("unknown_bits must be in range [1, 24]")

    plaintext = message.encode("utf-8")
    encryptor = A51Cipher(real_key, frame_number)
    initial_r1 = encryptor.state.r1
    initial_r2 = encryptor.state.r2
    initial_r3 = encryptor.state.r3

    keystream = encryptor.keystream_bytes(len(plaintext))
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))

    known_key_prefix = real_key >> unknown_bits
    attack = recover_keys_reduced_keyspace(
        known_plaintext=plaintext,
        ciphertext=ciphertext,
        frame_number=frame_number,
        known_key_prefix=known_key_prefix,
        unknown_bits=unknown_bits,
        max_candidates=1,
    )
    if not attack.candidates:
        raise RuntimeError("attack could not recover any key candidate in the configured keyspace")

    recovered_key = attack.candidates[0]
    decrypted = A51Cipher(recovered_key, frame_number).decrypt(ciphertext)

    return GuidedDemoResult(
        plaintext=plaintext,
        ciphertext=ciphertext,
        keystream=keystream,
        frame_number=frame_number,
        real_key=real_key,
        unknown_bits=unknown_bits,
        known_key_prefix=known_key_prefix,
        initial_r1=initial_r1,
        initial_r2=initial_r2,
        initial_r3=initial_r3,
        recovered_key=recovered_key,
        decrypted=decrypted,
        attack_elapsed_seconds=attack.elapsed_seconds,
    )
