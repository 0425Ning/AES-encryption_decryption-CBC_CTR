#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "aes.h"
#include "encrypt.h"
#include "decrypt.h"

#define BLOCK_SIZE 16 // AES block size in bytes
#define KEY_SIZE 17 // AES key size in bytes // 16 + 1(for the ending char '\0')
#define FILE_SIZE 50
#define AES_STR_LEN 8
#define AES_MODE_LEM 4
#define NONCE_SIZE 12
#define COUNTER_SIZE 4

void incrementCounter(uint8_t *counter, size_t size) {
    // Increment the counter by 1
    for (int i = size - 1; i >= 0; i--) {
        counter[i]++;
        if (counter[i] != 0) {
            // No carry, stop incrementing
            break;
        }
    }
}

uint8_t counter[COUNTER_SIZE];
uint8_t zero[COUNTER_SIZE] = {0};
static uint8_t padValue;
// Function to perform file encryption using AES
void encryptFile(FILE *inputFile, FILE *outputFile, const unsigned char * mode, uint8_t * iv) {

    if(strcmp(mode, "CTR") == 0)
    {
        memcpy(counter, zero, COUNTER_SIZE); // Initialize counter to zero
        // Copy counter after nonce
        memcpy(iv + NONCE_SIZE, counter, COUNTER_SIZE);
    }

    fseek(inputFile, 0L, SEEK_END);
    long fileSize = ftell(inputFile);
    rewind(inputFile);

    // Determine the number of blocks
    int numBlocks = fileSize / BLOCK_SIZE;
    padValue = BLOCK_SIZE - (fileSize % BLOCK_SIZE);
    
    if (fileSize % BLOCK_SIZE != 0) {
        numBlocks++;
    }

    uint8_t *inputBuffer = (uint8_t *)malloc(fileSize + padValue);
    if (!inputBuffer) {
        printf("Memory allocation error!\n");
        fclose(inputFile);
        fclose(outputFile);
        return;
    }

    // Read the entire file into inputBuffer
    fread(inputBuffer, sizeof(uint8_t), fileSize, inputFile);

    //inputBuffer = (uint8_t *)malloc(padValue);
    for (int i = 0; i < padValue; i++) {
        inputBuffer[fileSize + i] = padValue;
    }

    // Encrypt each block and write to output file
    uint8_t encryptedBlock[BLOCK_SIZE];
    for (int i = 0; i < numBlocks; i++) {
        uint8_t *blockStart = inputBuffer + (i * BLOCK_SIZE);
        AES_encrypt(blockStart, encryptedBlock, mode, iv);
        fwrite(encryptedBlock, sizeof(uint8_t), BLOCK_SIZE, outputFile);
        if(strcmp(mode, "CTR") == 0)
        {
            // Increment the counter for the next block
            incrementCounter(counter, sizeof(counter));
            memcpy(iv + NONCE_SIZE, counter, COUNTER_SIZE);
        }
    }

    free(inputBuffer);
    fclose(inputFile);
    fclose(outputFile);

    printf("\nFile encrypted successfully!\n");
}

void decryptFile(FILE* inputFile, FILE* outputFile,  const unsigned char * mode, uint8_t * iv) {

    if(strcmp(mode, "CTR") == 0)
    {
        memcpy(counter, zero, COUNTER_SIZE); // Initialize counter to zero
        // Copy counter after nonce
        memcpy(iv + NONCE_SIZE, counter, COUNTER_SIZE);
    }

    fseek(inputFile, 0L, SEEK_END);
    long fileSize = ftell(inputFile);
    rewind(inputFile);

    int numBlocks = fileSize / BLOCK_SIZE;
    if (fileSize % BLOCK_SIZE != 0) {
        numBlocks++;
    }

    uint8_t *inputBuffer = (uint8_t *)malloc(fileSize);
    if (!inputBuffer) {
        printf("inputBuffer Memory allocation error!\n");
        fclose(inputFile);
        fclose(outputFile);
        return;
    }

    fread(inputBuffer, sizeof(uint8_t), fileSize, inputFile);

    uint8_t *decryptedBuffer = (uint8_t *)malloc(fileSize);
    if (!decryptedBuffer) {
        printf("decryptedBuffer Memory allocation error!\n");
        //free(inputBuffer);
        fclose(outputFile);
        return;
    }

    for (int i = 0; i < numBlocks; i++) {
        uint8_t *blockStart = inputBuffer + (i * BLOCK_SIZE);
        if(strcmp(mode, "CTR") == 0)
        {
            AES_encrypt(blockStart, decryptedBuffer + (i * BLOCK_SIZE), mode, iv);
            // Increment the counter for the next block
            incrementCounter(counter, sizeof(counter));
            memcpy(iv + NONCE_SIZE, counter, COUNTER_SIZE);
        }
        else
        {
            AES_decrypt(blockStart, decryptedBuffer + (i * BLOCK_SIZE), mode, iv);
        }
    }

    padValue = decryptedBuffer[fileSize - 1];
    fileSize -= padValue;

    fwrite(decryptedBuffer, sizeof(uint8_t), fileSize, outputFile);
    fclose(inputFile);
    fclose(outputFile);

    free(inputBuffer);
    free(decryptedBuffer);

    printf("\nFile decrypted successfully!\n");
}

int main() {
    unsigned char aes_str[AES_STR_LEN];
    unsigned char aes_mode[AES_MODE_LEM];
    FILE *input_file, *encrypted_file, *encrypted_file2, *decrypted_file; // input file pointer, output(writer) file pointer

    char plaintext_fileName[FILE_SIZE];
    char ciphtertext_fileName[FILE_SIZE];
    char decrypted_fileName[FILE_SIZE];
    unsigned char key[KEY_SIZE];         // Main key(input key Ex. AES-128(16 char), AES-256(32 char)), the key that you input
    int key_length;

    uint8_t iv[BLOCK_SIZE]; //CBC CTR
    uint8_t nonce[NONCE_SIZE]; //CTR

    do {
        printf("Enter aes_enc or aes_dec to encrypt or decrypt the file: ");
        scanf("%s", &aes_str);
    } while (strcmp(aes_str, "aes_enc") != 0 && strcmp(aes_str, "aes_dec") != 0);

    /*if(strcmp(aes_str, "aes_enc") == 0)
    {*/
        do {
            printf("Enter plaintext file name to encrypt => ");
            scanf("%s", &plaintext_fileName);
            input_file = fopen(plaintext_fileName, "rb");
        } while (!input_file);

        /* get output Ciphertext */
        do {
            printf("Enter the Ciphertext file name to write out the cipher => "); 
            scanf("%s", &ciphtertext_fileName); 
            encrypted_file = fopen(ciphtertext_fileName,"wb");
        } while (!encrypted_file);
    /*}
    else if(strcmp(aes_str, "aes_dec") == 0)
    {*/
        /*printf("Enter Ciphertext file name to decrypt => "); 
        scanf("%s", &ciphtertext_fileName);*/
        encrypted_file2 = fopen(ciphtertext_fileName,"rb");
        if (!encrypted_file2) {
            printf("Error opening encrypted file(read)!\n");
        }

        do {
            printf("Enter the Decrypted file name to write out the decrypt => "); 
            scanf("%s", &decrypted_fileName);
            decrypted_file = fopen(decrypted_fileName, "wb");
        } while (!decrypted_file);
    /*}*/

    do {
        printf("Enter the key (length %d): ", BLOCK_SIZE);
        scanf("%s", key);
        key_length = strlen(key);
    } while (key_length != BLOCK_SIZE);

    do {
        printf("Enter AES mode (Only CBC or CTR): ");
        scanf("%s", &aes_mode);
    } while (strcmp(aes_mode, "CBC") != 0 && strcmp(aes_mode, "CTR") != 0);

    // initial the random value
    srand((unsigned int)time(NULL));

    if(strcmp(aes_mode, "CBC") == 0)
    {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            iv[i] = (uint8_t)rand(); // generate the random value, and let it be uint8_t type
        }
    }
    else if(strcmp(aes_mode, "CTR") == 0)
    {
        for (int i = 0; i < NONCE_SIZE; i++) {
            nonce[i] = (uint8_t)rand(); // generate the random value, and let it be uint8_t type
        }
        memcpy(iv, nonce, NONCE_SIZE); // Copy nonce
    }
    
    KeyExpansion(key, RoundKey);

    encryptFile(input_file, encrypted_file, aes_mode, iv);
    decryptFile(encrypted_file2, decrypted_file, aes_mode, iv);

    fclose(input_file);
    fclose(encrypted_file);
    fclose(decrypted_file);

    printf("------------------------------------------------\n");
    printf("Encryption & Decryption process complete !! \n");

    return 0;
}
