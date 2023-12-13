# AES-encryption_decryption-CBC_CTR
This is a project that implement AES encryption and decryption with CBC and CTR algorithm. <br />
<br />

## Usage
```sh
# Compile
cd D:\\文件\\碩一上\\課程\\無線網路協定\\HW\\HW4\\112523059_馬寧_HW4\\src
gcc -o main main.c aes.c encrypt.c decrypt.c
# Run
./main
```
### Enter the required data
Enter aes_enc or aes_dec to encrypt or decrypt the file. <br />
Enter plaintext file name to encrypt. <br />
Enter the Ciphertext file name to write out the cipher. <br />
Enter the Decrypted file name to write out the decrypt. <br />
Enter the key (length 16 for block_size = 128). <br />
Enter AES mode (Only CBC or CTR). <br />
<br />

### Key Expansion
KeyExpansion: Let the key that you just entered expand. <br />
<br />

### Encryption
encryptFile: Let the file be encrypted. <br />
Then let the data in the file be divided into several data blocks of size BLOCK_SIZE. <br />
Calculate how many bytes are needed to fill a block, which has the remaining data. Let the calculated number of bytes be the padding value, and use the padding value to fill the block. <br />
<br />

AES_encrypt: <br />
If the mode is CBC, XOR the plaintext block with iv or ciphertext. If the mode is CTR, iv must be used as the state for subsequent encryption steps. <br />
To implement AES encryption, first, execute AddRoundKey with the initial value 0 (first round = 0), and then execute the four steps of SubBytes, ShiftRows, MixColumns, and AddRoundKey with Nr-1 times. <br />
Finally, execute the three steps of SubBytes, ShiftRows, and AddRoundKey. <br />
After that, if the mode is CBC, the encrypted result must be stored as state_save as the element to perform XOR with plaintext block before encryption. If the mode is CTR, the encrypted result must be XORed with the plaintext block as output. <br />
<br />

### Decryption
decryptFile: Let the file be decrypted. <br />
Then let the data in the file be divided into several data blocks of size BLOCK_SIZE. <br />
If the mode is CTR, combine the randomly generated nonce and the counter be the iv, and then do the AES_encrypt. <br />
<br />

AES_decrypt: <br />
To implement AES decryption, first, execute AddRoundKey with the initial value Nr (first round = Nr), and then execute the four steps of InvShiftRows, InvSubBytes, AddRoundKey, and InvMixColumns with Nr-1 times. <br />
Finally, execute the three steps of InvShiftRows, InvSubBytes, and AddRoundKey. <br />
After that, if the mode is CBC, the encrypted result must be XORed with the iv or previous ciphertext block as output. Also, store the input value, which is the state this time, as state_save. <br />
<br />

After deducting padding from the decryptedBuffer, write it into the output file. <br />
<br />