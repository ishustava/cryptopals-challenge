from __future__ import division
import itertools

CODES = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
ENGLISH_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 "
MOST_FREQUENT_ENGLISH_CHARS = "ETAOIN SHRDLU"

def hex_string_to_binary(hex_string):
     return bin(int(hex_string, 16))[2:].zfill(len(hex_string) * 4)

def base64_encode(hex_string):
     binary = hex_string_to_binary(hex_string)
     base64_chunks = [binary[i:i+6] for i in range(0, len(binary), 6)]
     padding = lambda bits: '0' * (6 - len(bits))
     return ''.join(CODES[int(bits + padding(bits), 2)] for bits in base64_chunks)

def base64_decode(base64_string):
     binary = ''.join('{0:06b}'.format(CODES.index(c)) for c in base64_string)
     num_trailing_zeros = len(binary) % 4
     binary = binary[:len(binary) - num_trailing_zeros]
     return '{0:x}'.format((int(binary, 2)))

def xor(buffer1, buffer2):
     return '{0:x}'.format((int(buffer1, 16) ^ int(buffer2, 16)))

def hex_to_ascii(hex_string):
     return ''.join(chr(int(hex_string[i:i+2], 16)) for i in range(0, len(hex_string), 2))

def ascii_to_hex(ascii_string):
     return ''.join('{0:02x}'.format(ord(c)) for c in ascii_string)

def score_text(text):
     text = text.upper()
     frequencies = {c: text.count(c) for c in MOST_FREQUENT_ENGLISH_CHARS}
     return sum(frequencies.values())

def create_single_char_cipher(char, length):
     return '{0:02x}'.format(ord(char)) * length

def create_multiple_char_cipher(chars, length):
     return ''.join('{0:02x}'.format(ord(chars[i % len(chars)])) for i in range(length))

def detect_single_char_XOR_cipher_from_string(hex_string):
     possible_ciphers = [create_single_char_cipher(char, len(hex_string)//2) for char in ENGLISH_CHARS]
     scores = {score_text(hex_to_ascii(xor(hex_string, cipher))): cipher for cipher in possible_ciphers}
     probable_cipher = scores[max(scores)]
     plaintext = hex_to_ascii(xor(hex_string, probable_cipher))
     return max(scores), probable_cipher[:2], plaintext

def encrypt_with_repeating_xor_key(key, plaintext):
     return xor(ascii_to_hex(plaintext), create_multiple_char_cipher(key, len(plaintext)))

def hamming_distance(text1, text2):
     binary_xor_result = '{0:b}'.format(int(xor(text1, text2), 16))
     return len(filter(lambda b: b == '1', binary_xor_result))

def detect_key_size(text_in_hex):
     possible_key_sizes = range(2, 41)
     normalized_hamming_distances = {}
     for k in possible_key_sizes:
          chunks = [text_in_hex[i:i+2*k] for i in range(0, 14*k, 2*k)]
          combinations_chunks = itertools.combinations(chunks[:10], 2)
          sum_hamming_distance = 0
          for c in combinations_chunks:
               sum_hamming_distance += hamming_distance(c[0], c[1])/k
          normalized_hamming_distances[k] = sum_hamming_distance / 36
     return min(normalized_hamming_distances, key=normalized_hamming_distances.get)

def break_repeating_key_xor(base64_encoded_text):
     decoded_text = base64_decode(base64_encoded_text.replace('=', ''))
     probable_key_size = detect_key_size(decoded_text)
     single_chars = [decoded_text[i:i+2] for i in range(0, len(decoded_text)-1, 2)]
     single_char_blocks = [single_chars[i::probable_key_size] for i in range(probable_key_size)]
     key_decrypted_text_pairs = [detect_single_char_XOR_cipher_from_string(''.join(s)) for s in single_char_blocks]
     decrypted_text_single_char_blocks = [x[2] for x in key_decrypted_text_pairs]
     return ''.join([''.join(x[i] for x in decrypted_text_single_char_blocks) for i in range(probable_key_size)])

