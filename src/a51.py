from __future__ import annotations

from dataclasses import dataclass


def _majority(a: int, b: int, c: int) -> int:
    return 1 if (a + b + c) >= 2 else 0


@dataclass
class A51State:
    r1: int = 0  # 19 bits
    r2: int = 0  # 22 bits
    r3: int = 0  # 23 bits


class A51Cipher:
    """
    Educational A5/1 stream cipher implementation.
    Uses a 64-bit session key and 22-bit frame number.
    """

    R1_LEN = 19
    R2_LEN = 22
    R3_LEN = 23

    R1_MASK = (1 << R1_LEN) - 1
    R2_MASK = (1 << R2_LEN) - 1
    R3_MASK = (1 << R3_LEN) - 1

    # LSB-based tap indexing
    R1_TAPS = (13, 16, 17, 18)
    R2_TAPS = (20, 21)
    R3_TAPS = (7, 20, 21, 22)

    R1_CLOCK_BIT = 8
    R2_CLOCK_BIT = 10
    R3_CLOCK_BIT = 10

    def __init__(self, key: int, frame_number: int) -> None:
        if key < 0 or key >= (1 << 64):
            raise ValueError("key must be a 64-bit integer")
        if frame_number < 0 or frame_number >= (1 << 22):
            raise ValueError("frame_number must be a 22-bit integer")
        self.key = key
        self.frame_number = frame_number
        self.state = self._initialize_state(key, frame_number)

    @staticmethod
    def _xor_taps(register: int, taps: tuple[int, ...]) -> int:
        out = 0
        for t in taps:
            out ^= (register >> t) & 1
        return out

    @classmethod
    def _clock_register(
        cls, register: int, length: int, mask: int, taps: tuple[int, ...], input_bit: int = 0
    ) -> int:
        feedback = cls._xor_taps(register, taps) ^ input_bit
        register = ((register << 1) & mask) | feedback
        return register

    def _initialize_state(self, key: int, frame_number: int) -> A51State:
        state = A51State()

        # Load key bits (LSB-first)
        for i in range(64):
            key_bit = (key >> i) & 1
            state.r1 = self._clock_register(state.r1, self.R1_LEN, self.R1_MASK, self.R1_TAPS, key_bit)
            state.r2 = self._clock_register(state.r2, self.R2_LEN, self.R2_MASK, self.R2_TAPS, key_bit)
            state.r3 = self._clock_register(state.r3, self.R3_LEN, self.R3_MASK, self.R3_TAPS, key_bit)

        # Load frame bits (LSB-first)
        for i in range(22):
            frame_bit = (frame_number >> i) & 1
            state.r1 = self._clock_register(
                state.r1, self.R1_LEN, self.R1_MASK, self.R1_TAPS, frame_bit
            )
            state.r2 = self._clock_register(
                state.r2, self.R2_LEN, self.R2_MASK, self.R2_TAPS, frame_bit
            )
            state.r3 = self._clock_register(
                state.r3, self.R3_LEN, self.R3_MASK, self.R3_TAPS, frame_bit
            )

        # Warm-up
        for _ in range(100):
            self._irregular_clock(state)

        return state

    def _irregular_clock(self, state: A51State) -> None:
        c1 = (state.r1 >> self.R1_CLOCK_BIT) & 1
        c2 = (state.r2 >> self.R2_CLOCK_BIT) & 1
        c3 = (state.r3 >> self.R3_CLOCK_BIT) & 1
        m = _majority(c1, c2, c3)

        if c1 == m:
            state.r1 = self._clock_register(state.r1, self.R1_LEN, self.R1_MASK, self.R1_TAPS)
        if c2 == m:
            state.r2 = self._clock_register(state.r2, self.R2_LEN, self.R2_MASK, self.R2_TAPS)
        if c3 == m:
            state.r3 = self._clock_register(state.r3, self.R3_LEN, self.R3_MASK, self.R3_TAPS)

    def next_bit(self) -> int:
        self._irregular_clock(self.state)
        b1 = (self.state.r1 >> (self.R1_LEN - 1)) & 1
        b2 = (self.state.r2 >> (self.R2_LEN - 1)) & 1
        b3 = (self.state.r3 >> (self.R3_LEN - 1)) & 1
        return b1 ^ b2 ^ b3

    def keystream_bits(self, n_bits: int) -> list[int]:
        if n_bits < 0:
            raise ValueError("n_bits must be non-negative")
        return [self.next_bit() for _ in range(n_bits)]

    def keystream_bytes(self, n_bytes: int) -> bytes:
        if n_bytes < 0:
            raise ValueError("n_bytes must be non-negative")
        bits = self.keystream_bits(n_bytes * 8)
        out = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for bit_index in range(8):
                byte |= bits[i + bit_index] << bit_index
            out.append(byte)
        return bytes(out)

    def encrypt(self, plaintext: bytes) -> bytes:
        ks = self.keystream_bytes(len(plaintext))
        return bytes(p ^ k for p, k in zip(plaintext, ks))

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.encrypt(ciphertext)

