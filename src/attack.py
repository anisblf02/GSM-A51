from __future__ import annotations

from dataclasses import dataclass
from random import Random
from time import perf_counter

from src.a51 import A51Cipher


@dataclass
class AttackResult:
    candidates: list[int]
    tried_keys: int
    elapsed_seconds: float
    known_keystream_bytes: int


@dataclass
class AttackSweepPoint:
    length_bytes: int
    candidate_count: int
    success: bool
    unique_recovery: bool
    elapsed_seconds: float


@dataclass
class AttackRatePoint:
    length_bytes: int
    trials: int
    success_rate: float
    unique_recovery_rate: float
    avg_candidate_count: float
    avg_elapsed_seconds: float


def derive_keystream_from_known_plaintext(known_plaintext: bytes, ciphertext: bytes) -> bytes:
    if len(known_plaintext) != len(ciphertext):
        raise ValueError("known_plaintext and ciphertext must have the same length")
    return bytes(p ^ c for p, c in zip(known_plaintext, ciphertext))


def recover_keys_reduced_keyspace(
    known_plaintext: bytes,
    ciphertext: bytes,
    frame_number: int,
    known_key_prefix: int,
    unknown_bits: int,
    max_candidates: int = 10,
) -> AttackResult:
    """
    Educational known-plaintext attack simulator.

    This does NOT break full A5/1 keyspace. It brute-forces a reduced keyspace where
    only `unknown_bits` of the 64-bit key are unknown and the remaining prefix bits
    are assumed known.
    """

    if unknown_bits < 1 or unknown_bits > 24:
        raise ValueError("unknown_bits must be in range [1, 24] for practical simulation")
    if len(known_plaintext) == 0:
        raise ValueError("known_plaintext cannot be empty")
    if len(known_plaintext) != len(ciphertext):
        raise ValueError("known_plaintext and ciphertext must have the same length")
    if frame_number < 0 or frame_number >= (1 << 22):
        raise ValueError("frame_number must be a 22-bit integer")
    if known_key_prefix < 0 or known_key_prefix >= (1 << (64 - unknown_bits)):
        raise ValueError("known_key_prefix does not fit the specified unknown_bits")
    if max_candidates < 1:
        raise ValueError("max_candidates must be positive")

    observed_keystream = derive_keystream_from_known_plaintext(known_plaintext, ciphertext)
    suffix_space = 1 << unknown_bits
    key_prefix_shifted = known_key_prefix << unknown_bits
    candidates: list[int] = []
    tried_keys = 0
    start = perf_counter()

    for suffix in range(suffix_space):
        tried_keys += 1
        key = key_prefix_shifted | suffix
        candidate_keystream = A51Cipher(key, frame_number).keystream_bytes(len(observed_keystream))
        if candidate_keystream == observed_keystream:
            candidates.append(key)
            if len(candidates) >= max_candidates:
                break

    elapsed = perf_counter() - start
    return AttackResult(
        candidates=candidates,
        tried_keys=tried_keys,
        elapsed_seconds=elapsed,
        known_keystream_bytes=len(observed_keystream),
    )


def sweep_known_plaintext_lengths(
    real_key: int,
    frame_number: int,
    known_key_prefix: int,
    unknown_bits: int,
    plaintext: bytes,
    lengths: list[int],
) -> list[AttackSweepPoint]:
    if len(plaintext) == 0:
        raise ValueError("plaintext cannot be empty")
    if not lengths:
        raise ValueError("lengths cannot be empty")

    ciphertext = A51Cipher(real_key, frame_number).encrypt(plaintext)
    results: list[AttackSweepPoint] = []
    suffix_space = 1 << unknown_bits

    for length in lengths:
        if length < 1 or length > len(plaintext):
            raise ValueError("each length must be in range [1, len(plaintext)]")

        attack = recover_keys_reduced_keyspace(
            known_plaintext=plaintext[:length],
            ciphertext=ciphertext[:length],
            frame_number=frame_number,
            known_key_prefix=known_key_prefix,
            unknown_bits=unknown_bits,
            max_candidates=suffix_space,
        )
        candidate_count = len(attack.candidates)
        results.append(
            AttackSweepPoint(
                length_bytes=length,
                candidate_count=candidate_count,
                success=real_key in attack.candidates,
                unique_recovery=(candidate_count == 1 and real_key in attack.candidates),
                elapsed_seconds=attack.elapsed_seconds,
            )
        )

    return results


def evaluate_attack_success_rates(
    frame_number: int,
    unknown_bits: int,
    lengths: list[int],
    trials: int,
    seed: int = 0,
) -> list[AttackRatePoint]:
    if trials < 1:
        raise ValueError("trials must be positive")
    if unknown_bits < 1 or unknown_bits > 24:
        raise ValueError("unknown_bits must be in range [1, 24] for practical simulation")
    if not lengths:
        raise ValueError("lengths cannot be empty")

    max_len = max(lengths)
    if max_len < 1:
        raise ValueError("lengths must be >= 1")

    rng = Random(seed)
    suffix_space = 1 << unknown_bits
    per_length_success = {length: 0 for length in lengths}
    per_length_unique = {length: 0 for length in lengths}
    per_length_candidates = {length: 0 for length in lengths}
    per_length_elapsed = {length: 0.0 for length in lengths}

    for _ in range(trials):
        real_key = rng.getrandbits(64)
        known_key_prefix = real_key >> unknown_bits
        plaintext = bytes(rng.getrandbits(8) for _ in range(max_len))
        ciphertext = A51Cipher(real_key, frame_number).encrypt(plaintext)

        for length in lengths:
            if length < 1 or length > max_len:
                raise ValueError("each length must be in range [1, max(lengths)]")

            attack = recover_keys_reduced_keyspace(
                known_plaintext=plaintext[:length],
                ciphertext=ciphertext[:length],
                frame_number=frame_number,
                known_key_prefix=known_key_prefix,
                unknown_bits=unknown_bits,
                max_candidates=suffix_space,
            )
            candidate_count = len(attack.candidates)
            per_length_candidates[length] += candidate_count
            per_length_elapsed[length] += attack.elapsed_seconds

            if real_key in attack.candidates:
                per_length_success[length] += 1
            if candidate_count == 1 and real_key in attack.candidates:
                per_length_unique[length] += 1

    points: list[AttackRatePoint] = []
    for length in lengths:
        points.append(
            AttackRatePoint(
                length_bytes=length,
                trials=trials,
                success_rate=per_length_success[length] / trials,
                unique_recovery_rate=per_length_unique[length] / trials,
                avg_candidate_count=per_length_candidates[length] / trials,
                avg_elapsed_seconds=per_length_elapsed[length] / trials,
            )
        )
    return points
