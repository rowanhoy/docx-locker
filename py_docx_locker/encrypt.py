import hashlib
import os
import base64


class DocxEncrypt:
    def __init__(
        self,
        spin_count: int,
        key_hash: str,
        salt_hash: str,
        algo_sid: int = 14,
        algo_type: str = "typeAny",
        algo_class: str = "hash",
        provider_type: str = "rsaAES"
    ):
        self.spin_count = spin_count
        self.key_hash = key_hash
        self.salt_hash = salt_hash
        self.algo_sid = algo_sid
        self.algo_type = algo_type
        self.algo_class = algo_class
        self.providerType = provider_type


# Constants used in the legacy hash computation
InitialCodeArray = [
    0xE1F0, 0x1D0F, 0xCC9C, 0x84C0, 0x110C,
    0x0E10, 0xF1CE, 0x313E, 0x1872, 0xE139,
    0xD40F, 0x84F9, 0x280C, 0xA96A, 0x4EC3
]

EncryptionMatrix = [
    [0xAEFC, 0x4DD9, 0x9BB2, 0x2745, 0x4E8A, 0x9D14, 0x2A09],
    [0x7B61, 0xF6C2, 0xFDA5, 0xEB6B, 0xC6F7, 0x9DCF, 0x2BBF],
    [0x4563, 0x8AC6, 0x05AD, 0x0B5A, 0x16B4, 0x2D68, 0x5AD0],
    [0x0375, 0x06EA, 0x0DD4, 0x1BA8, 0x3750, 0x6EA0, 0xDD40],
    [0xD849, 0xA0B3, 0x5147, 0xA28E, 0x553D, 0xAA7A, 0x44D5],
    [0x6F45, 0xDE8A, 0xAD35, 0x4A4B, 0x9496, 0x390D, 0x721A],
    [0xEB23, 0xC667, 0x9CEF, 0x29FF, 0x53FE, 0xA7FC, 0x5FD9],
    [0x47D3, 0x8FA6, 0x0F6D, 0x1EDA, 0x3DB4, 0x7B68, 0xF6D0],
    [0xB861, 0x60E3, 0xC1C6, 0x93AD, 0x377B, 0x6EF6, 0xDDEC],
    [0x45A0, 0x8B40, 0x06A1, 0x0D42, 0x1A84, 0x3508, 0x6A10],
    [0xAA51, 0x4483, 0x8906, 0x022D, 0x045A, 0x08B4, 0x1168],
    [0x76B4, 0xED68, 0xCAF1, 0x85C3, 0x1BA7, 0x374E, 0x6E9C],
    [0x3730, 0x6E60, 0xDCC0, 0xA9A1, 0x4363, 0x86C6, 0x1DAD],
    [0x3331, 0x6662, 0xCCC4, 0x89A9, 0x0373, 0x06E6, 0x0DCC],
    [0x1021, 0x2042, 0x4084, 0x8108, 0x1231, 0x2462, 0x48C4]
]

# non standard hashing algorithm for docx


def create_hash(password: str) -> str:
    generated_key = bytearray(4)  # 4-byte array
    max_password_length = 15

    # Truncate to 15 characters
    password = password[:max_password_length]

    arr_byte_chars = bytearray(
        (ord(c) & 0x00FF) if (ord(c) & 0x00FF) != 0 else ((ord(c) & 0xFF00) >> 8)
        for c in password
    )

    high_order_word = InitialCodeArray[len(arr_byte_chars) - 1]

    for i, byte_char in enumerate(arr_byte_chars):
        tmp = max_password_length - len(arr_byte_chars) + i
        for bit_index in range(7):
            if byte_char & (1 << bit_index):
                high_order_word ^= EncryptionMatrix[tmp][bit_index]

    verifier = 0

    # Reversed iteration over arr_byte_chars
    for byte_char in reversed(arr_byte_chars):
        # Rotate left base 15 bits
        intermediate1 = 0 if (verifier & 0x4000) == 0 else 1
        intermediate2 = (verifier << 1) & 0x7FFF
        verifier = intermediate1 | intermediate2

        verifier ^= byte_char

    # Final rotation and XOR operations
    intermediate1 = 0 if (verifier & 0x4000) == 0 else 1
    intermediate2 = (verifier << 1) & 0x7FFF
    verifier = intermediate1 | intermediate2

    verifier ^= len(arr_byte_chars)
    verifier ^= 0xCE4B

    # Assemble the generated key
    generated_key[0:2] = verifier.to_bytes(2, byteorder='little', signed=False)
    generated_key[2:4] = high_order_word.to_bytes(
        2, byteorder='little', signed=False)

    # Convert generated_key to hex string in little-endian order
    hash = ''.join(f'{b:02X}' for b in generated_key)

    return hash


def generate_docx_protection(password: str, provided_salt: str = None, spins: int = None) -> DocxEncrypt:
    # Use provided salt or generate a new one
    salt = base64.b64decode(provided_salt) if provided_salt else os.urandom(16)
    spin_count = spins if spins else 100000

    password_hash = create_hash(password)

    password_bytes = password_hash.encode('utf-16le')

    hash_value = hashlib.sha512(salt + password_bytes).digest()

    for i in range(spin_count):
        iterator = i.to_bytes(4, byteorder='little')
        hash_value = hashlib.sha512(hash_value + iterator).digest()

    # Encode salt and hash in Base64
    salt_b64 = base64.b64encode(salt).decode('ascii')
    hash_b64 = base64.b64encode(hash_value).decode('ascii')

    return DocxEncrypt(spin_count, hash_b64, salt_b64)
