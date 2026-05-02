from src.a51 import A51Cipher


def test_encrypt_decrypt_roundtrip():
    key = 0x123456789ABCDEF0
    frame = 0x13456
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")

    enc = A51Cipher(key, frame).encrypt(plain)
    dec = A51Cipher(key, frame).decrypt(enc)

    assert dec == plain


def test_deterministic_keystream():
    key = 0x1F1E1D1C1B1A1918
    frame = 0x2AAAA

    ks1 = A51Cipher(key, frame).keystream_bits(128)
    ks2 = A51Cipher(key, frame).keystream_bits(128)

    assert ks1 == ks2
