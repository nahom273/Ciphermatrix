import numpy as np
import re

class MatrixModEncryptor:
    def __init__(self, encryptionKey_str,start_index):
        self.start_index = start_index
        self.charset = ''.join(chr(i) for i in range(128))
        self.charset_size = len(self.charset)
        try:
            E_flat = [int(x.strip()) for x in encryptionKey_str.split(',')]
            matrix_size = int(len(E_flat) ** 0.5)
            if len(E_flat) != matrix_size ** 2:
                raise ValueError("The length of encryptionKey must be a perfect square. eg.2,4,9,16,25 ...")
            self.E = np.array(E_flat).reshape(matrix_size, matrix_size)
        except ValueError as e:
            raise ValueError(f"Invalid Encryption key format or value: {e}")
        
        self.D = self._mod_inv(self.E, self.charset_size)

    def _char_to_num(self, char):
        return self.charset.index(char) + self.start_index

    def _num_to_char(self, num):
        num = num - self.start_index
        return self.charset[num % self.charset_size]

    def _text_to_numbers(self, text):
        return [self._char_to_num(c) for c in text]

    def _numbers_to_text(self, numbers):
        return ''.join(self._num_to_char(n) for n in numbers)

    def _pad_text(self, text, block_size):
        pad_len = block_size - (len(text) % block_size)
        text += self.charset[-1] * pad_len
        return text, pad_len

    def _mod_inv(self, matrix, modulus):
        det = int(np.round(np.linalg.det(matrix)))
        det_inv = pow(det, -1, modulus)
        matrix_inv = np.round(det_inv * np.linalg.det(matrix) * np.linalg.inv(matrix)).astype(int)
        return matrix_inv % modulus

    def encrypt(self, plaintext):
        plaintext, pad_len = self._pad_text(plaintext, len(self.E))
        plaintext_numbers = self._text_to_numbers(plaintext)
        num_blocks = len(plaintext_numbers) // len(self.E)
        encrypted_numbers = []

        for i in range(num_blocks):
            block = np.array(plaintext_numbers[i*len(self.E):(i+1)*len(self.E)])
            encrypted_block = np.dot(self.E, block) % self.charset_size
            encrypted_numbers.extend(encrypted_block)

        return f"_{pad_len}_" + self._numbers_to_text(encrypted_numbers)

    def decrypt(self, ciphertext):
        match = re.match(r"_(\d+)_(.*)", ciphertext)
        pad_len = int(match.group(1))
        ciphertext = match.group(2)
        ciphertext_numbers = self._text_to_numbers(ciphertext)
        num_blocks = len(ciphertext_numbers) // len(self.D)
        decrypted_numbers = []

        for i in range(num_blocks):
            block = np.array(ciphertext_numbers[i*len(self.D):(i+1)*len(self.D)])
            decrypted_block = np.dot(self.D, block) % self.charset_size
            decrypted_numbers.extend(decrypted_block)

        decrypted_text = self._numbers_to_text(decrypted_numbers)
        return decrypted_text[:-pad_len]

# Assuming the E_flat is taken from an environment variable as a string like '3,5,1,2'
encryptionKey_str = '3,5,1,4,5,6,7,5,2' # Default value as a fallback
encryptor1 = MatrixModEncryptor(encryptionKey_str,3)


plaintext = "Use a"
encrypted1 = encryptor1.encrypt(plaintext)

print(f"Encrypted: {encrypted1}",'1=================')

decrypted1 = encryptor1.decrypt(encrypted1)

print(f"Decrypted: {decrypted1}")

