def sha512_compression(w, round_constants, a, b, c, d, e, f, g, h):
    if len(round_constants) < 80:
        raise ValueError("Not enough round constants for SHA-512.")

    for i in range(80):
        if 0 <= i < 16:
            f = (b & c) | ((~b) & d)
            g = i
        elif 16 <= i < 32:
            f = (d & b) | ((~d) & c)
            g = (5 * i + 1) % 16
        elif 32 <= i < 48:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        elif 48 <= i < 64:
            f = c ^ (b | (~d))
            g = (7 * i) % 16

        # Ensure that w[i % 16] is not empty before converting it to an integer
        if w[i % 16]:
            temp = (h + f + round_constants[i] + w[i % 16]) & 0xFFFFFFFFFFFFFFFF
        else:
            temp = (h + f + round_constants[i]) & 0xFFFFFFFFFFFFFFFF

        h = g
        g = f
        f = e
        e = (d + temp) & 0xFFFFFFFFFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp + a) & 0xFFFFFFFFFFFFFFFF

    a = (a + 0x6a09e667f3bcc908) & 0xFFFFFFFFFFFFFFFF
    b = (b + 0xbb67ae8584caa73b) & 0xFFFFFFFFFFFFFFFF
    c = (c + 0x3c6ef372fe94f82b) & 0xFFFFFFFFFFFFFFFF
    d = (d + 0xa54ff53a5f1d36f1) & 0xFFFFFFFFFFFFFFFF
    e = (e + 0x510e527fade682d1) & 0xFFFFFFFFFFFFFFFF
    f = (f + 0x9b05688c2b3e6c1f) & 0xFFFFFFFFFFFFFFFF
    g = (g + 0x1f83d9abfb41bd6b) & 0xFFFFFFFFFFFFFFFF
    h = (h + 0x5be0cd19137e2179) & 0xFFFFFFFFFFFFFFFF

    return a, b, c, d, e, f, g, h


# Sample round_constants as decimal values
round_constants = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
]
def binary_padding(message_binary):
    # Calculate the length of the original message in bits
    original_length = len(message_binary)

    # Calculate the number of bits needed to reach a multiple of 1024 bits
    padding_length = (1024 - (original_length + 1 + 128) % 1024) % 1024

    # Append '1' bit
    padded_message = message_binary + '1'

    # Append '0' bits to reach the required length
    padded_message += '0' * padding_length

    # Append the original message length as a 128-bit binary representation
    padded_message += format(original_length, '0128b')

    return padded_message

def divide_padded_binary(block):
    # Split the padded message into 1024-bit blocks and convert them to a list of 64 16-bit words.
    words = []
    for i in range(0, 1024, 16):
        word = block[i:i + 16]
        words.append(int(word, 2))
    return words

def process_message(message):
    a, b, c, d, e, f, g, h = 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    message_bytes = message.encode('utf-8')
    message_binary = ''.join(format(byte, '08b') for byte in message_bytes)
    padded_message = binary_padding(message_binary)
    blocks = [padded_message[i:i + 1024] for i in range(0, len(padded_message), 1024)]

    for block in blocks:
        w = divide_padded_binary(block)
        a, b, c, d, e, f, g, h = sha512_compression(w, round_constants, a, b, c, d, e, f, g, h)

    hash_result = f"{a:016x}{b:016x}{c:016x}{d:016x}{e:016x}{f:016x}{g:016x}{h:016x}"
    return hash_result

# Sample round_constants as decimal values (already defined in your code)

# Example usage:
hashed_message = process_message("Sakar")
print("SHA-512 Hash:", hashed_message)
