from src.a51 import A51Cipher
from src.attack import (
    derive_keystream_from_known_plaintext,
    evaluate_attack_success_rates,
    recover_keys_reduced_keyspace,
    sweep_known_plaintext_lengths,
)


def test_derive_keystream_from_known_plaintext():
    plaintext = bytes.fromhex("00112233")
    keystream = bytes.fromhex("a1b2c3d4")
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))

    derived = derive_keystream_from_known_plaintext(plaintext, ciphertext)
    assert derived == keystream


def test_recover_key_reduced_keyspace_reproducible_demo():
    # Fixed, reproducible live-demo scenario
    real_key = 0x123456789ABCDEF0
    frame = 0x13456
    unknown_bits = 12
    known_key_prefix = real_key >> unknown_bits

    known_plaintext = b"GSM-A51-DEMO-BLOCK"
    ciphertext = A51Cipher(real_key, frame).encrypt(known_plaintext)

    result = recover_keys_reduced_keyspace(
        known_plaintext=known_plaintext,
        ciphertext=ciphertext,
        frame_number=frame,
        known_key_prefix=known_key_prefix,
        unknown_bits=unknown_bits,
        max_candidates=5,
    )

    assert real_key in result.candidates
    assert result.tried_keys == (1 << unknown_bits)
    assert result.known_keystream_bytes == len(known_plaintext)


def test_sweep_known_plaintext_lengths_monotonic_candidates():
    real_key = 0x123456789ABCDEF0
    frame = 0x13456
    unknown_bits = 12
    known_key_prefix = real_key >> unknown_bits
    plaintext = b"GSM-A51-DEMO-BLOCK"

    points = sweep_known_plaintext_lengths(
        real_key=real_key,
        frame_number=frame,
        known_key_prefix=known_key_prefix,
        unknown_bits=unknown_bits,
        plaintext=plaintext,
        lengths=[1, 2, 4, 8, len(plaintext)],
    )

    counts = [p.candidate_count for p in points]
    assert counts == sorted(counts, reverse=True)
    assert points[-1].unique_recovery is True


def test_evaluate_attack_success_rates_structure_and_monotonicity():
    points = evaluate_attack_success_rates(
        frame_number=0x13456,
        unknown_bits=10,
        lengths=[1, 2, 3, 4],
        trials=8,
        seed=7,
    )

    assert len(points) == 4
    success_rates = [p.success_rate for p in points]
    unique_rates = [p.unique_recovery_rate for p in points]
    avg_candidates = [p.avg_candidate_count for p in points]

    assert all(0.0 <= s <= 1.0 for s in success_rates)
    assert all(0.0 <= s <= 1.0 for s in unique_rates)
    assert avg_candidates == sorted(avg_candidates, reverse=True)
    assert unique_rates == sorted(unique_rates)
