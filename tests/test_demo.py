from src.demo import run_guided_demo


def test_run_guided_demo_end_to_end():
    result = run_guided_demo(
        message="GSM-A51-DEMO-BLOCK",
        real_key=0x123456789ABCDEF0,
        frame_number=0x13456,
        unknown_bits=12,
    )

    assert result.recovered_key == 0x123456789ABCDEF0
    assert result.decrypted == b"GSM-A51-DEMO-BLOCK"
    assert len(result.keystream) == len(result.plaintext)
    assert len(result.ciphertext) == len(result.plaintext)

