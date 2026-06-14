"""Safe toy XOR loop used for AIDebug documentation examples.

This script decodes a local string only. It does not execute code, persist,
evade analysis, or communicate over the network.
"""


def xor_decode(data: bytes, key: int) -> str:
    return bytes(byte ^ key for byte in data).decode("utf-8")


def main() -> None:
    encoded = bytes([0x26, 0x27, 0x2F, 0x2D, 0x6C, 0x2E, 0x2D, 0x21, 0x23, 0x2E])
    print(xor_decode(encoded, 0x42))


if __name__ == "__main__":
    main()
