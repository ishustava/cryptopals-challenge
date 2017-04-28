import unittest
from set1 import to_base64
from set1 import xor
from set1 import detect_single_char_XOR_cipher_from_string
from set1 import encrypt_with_repeating_xor_key
from set1 import hamming_distance

class TestCryptoPalsSet1(unittest.TestCase):
     def error_message(self, expected, actual):
         return "\nExpected: " + str(expected) + ", but got: " + str(actual)

     # #1
     def test_base_64(self):
          base64_result = to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
          expected_result = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
          self.assertEqual(base64_result,
                           expected_result,
                           "Wrong encoded base64 result." + self.error_message(expected_result, base64_result))

          base64_result = to_base64("abcd")
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
                    '58585858585858585858585858585858585858585858585858585858585858585858', \
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
          distance = hamming_distance('this is a test', 'wokka wokka!!!')
          self.assertEqual(distance, 37, "Wrong hamming distance." + self.error_message(37, distance))

if __name__ == '__main__':
     unittest.main()
