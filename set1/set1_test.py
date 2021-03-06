import unittest
from set1 import base64_encode
from set1 import base64_decode
from set1 import xor
from set1 import detect_single_char_XOR_cipher_from_string
from set1 import encrypt_with_repeating_xor_key
from set1 import hamming_distance
from set1 import detect_key_size
from set1 import ascii_to_hex
from set1 import break_repeating_key_xor
import random

class TestCryptoPalsSet1(unittest.TestCase):
     def error_message(self, expected, actual):
         return "\nExpected: " + str(expected) + ", but got: " + str(actual)

     # #1
     def test_base64_encode(self):
          base64_result = base64_encode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
          expected_result = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
          self.assertEqual(base64_result,
                           expected_result,
                           "Wrong encoded base64 result." + self.error_message(expected_result, base64_result))

          base64_result = base64_encode("abcd")
          expected_result = 'q80'
          self.assertEqual(base64_result,
                           expected_result,
                           "Wrong encoded base64 result." + self.error_message(expected_result, base64_result))

     # #2
     def test_fixed_xor(self):
          # print "Running 'Fixed XOR'"
          result = xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965')
          expected_result = '746865206b696420646f6e277420706c6179'
          self.assertEqual(result,
                           expected_result,
                           "Wrong result for 'Fixed XOR'." + self.error_message(expected_result, result))

     # #3
     def test_single_byte_xor_cipher(self):
          # print "Running 'Single-byte XOR cipher'"
          hex_string = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
          _, cipher, plaintext = detect_single_char_XOR_cipher_from_string(hex_string)
          expected_cipher, expected_plaintext = \
                    '58', \
                    'Cooking MC\'s like a pound of bacon'
          self.assertEqual(cipher,
                           expected_cipher,
                           "Detected a wrong cipher." + self.error_message(expected_cipher, cipher))
          self.assertEqual(plaintext,
                           expected_plaintext,
                           "Detected a wrong plaintext." + self.error_message(expected_plaintext, plaintext))

     # #4
     def test_detect_single_char_xor(self):
          # print "Running 'Detect single-character XOR'"
          scores = {}
          for line in open("4.txt", "r").readlines():
               score, cipher, text = detect_single_char_XOR_cipher_from_string(line)
               scores[score] = (cipher, text)
          detected_cipher, detected_plaintext = scores[max(scores)]
          expected_plaintext = 'Now that the party is jumping\n'
          self.assertEqual(detected_plaintext,
                           expected_plaintext,
                           "Detected a wrong plaintext." + self.error_message(expected_plaintext, detected_plaintext))

     # #5
     def test_repeating_key_xor(self):
          # print "Running 'Implement repeating-key XOR'"
          plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
          result = encrypt_with_repeating_xor_key("ICE", plaintext)
          expected_ciphertext = "b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
          self.assertEqual(result,
                           expected_ciphertext,
                           "Wrong repeating xor key result." + self.error_message(expected_ciphertext, result))

     # #6
     def test_hamming_distance(self):
          distance = hamming_distance(ascii_to_hex('this is a test'), ascii_to_hex('wokka wokka!!!'))
          self.assertEqual(distance, 37, "Wrong hamming distance." + self.error_message(37, distance))

     def test_detect_key_size(self):
          plaintext = """Horatio says 'tis but our fantasy,
And will not let belief take hold of him
Touching this dreaded sight, twice seen of us:
Therefore I have entreated him along
With us to watch the minutes of this night;
That if again this apparition come,
He may approve our eyes and speak to it."""

          chars = 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz'
          num_successful_detections = 0
          for k in range(2, 40):
               key = ''.join(random.sample(chars, k))
               print "key: ", key, " for size: ", k
               ciphertext = encrypt_with_repeating_xor_key(key, plaintext)
               detected_key_size = detect_key_size(ciphertext)
               print "detected key size:", detected_key_size
               if detected_key_size == k:
                    num_successful_detections += 1
          print "number of successfull detections:", num_successful_detections, num_successful_detections/38.0 * 100

     def test_base64_decode(self):
          hex_result = base64_decode('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')
          expected_result = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
          self.assertEqual(hex_result,
                           expected_result,
                           "Wrong decoded base64 result." + self.error_message(expected_result, hex_result))

          hex_result = base64_decode('q80')
          expected_result = 'abcd'
          self.assertEqual(hex_result,
                           expected_result,
                           "Wrong decoded base64 result." + self.error_message(expected_result, hex_result))

     def test_break_repeating_key_xor(self):
          encrypted_text_file = open("6.txt", "r")
          text = ''.join(line.strip() for line in encrypted_text_file.readlines())
          decrypted_text = break_repeating_key_xor(text)
          print decrypted_text

if __name__ == '__main__':
     unittest.main()
