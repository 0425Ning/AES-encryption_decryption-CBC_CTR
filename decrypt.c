#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "aes.h"
#include "decrypt.h"

// Inverse S-Box Substitution
void InvSubBytes(state_t *state) {
    for (int i = 0; i < Nb; ++i) {
        for (int j = 0; j < Nb; ++j) {
            (*state)[i][j] = inv_sbox[(*state)[i][j]];
        }
    }
}

// right(inverse) Circular Shift (row)
void InvShiftRows(state_t *state) {
    uint8_t temp;

    // Undo the shift in row 1 by 1 byte to the right
    temp = (*state)[1][3]; //row column
    (*state)[1][3] = (*state)[1][2];
    (*state)[1][2] = (*state)[1][1];
    (*state)[1][1] = (*state)[1][0];
    (*state)[1][0] = temp;

    // Undo the shift in row 2 by 2 bytes to the right
    temp = (*state)[2][0];
    (*state)[2][0] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp = (*state)[2][1];
    (*state)[2][1] = (*state)[2][3];
    (*state)[2][3] = temp;

    // Undo the shift in row 3 by 3 bytes to the right
    temp = (*state)[3][0];
    (*state)[3][0] = (*state)[3][1];
    (*state)[3][1] = (*state)[3][2];
    (*state)[3][2] = (*state)[3][3];
    (*state)[3][3] = temp;
}

void InvMixColumns(state_t *state) {
    uint8_t a, b, c, d;
    for (int i = 0; i < Nb; ++i) {
        a = (*state)[0][i];
        b = (*state)[1][i];
        c = (*state)[2][i];
        d = (*state)[3][i];

        (*state)[0][i] = Multiply(a, 0x0E) ^ Multiply(b, 0x0B) ^ Multiply(c, 0x0D) ^ Multiply(d, 0x09);
        (*state)[1][i] = Multiply(a, 0x09) ^ Multiply(b, 0x0E) ^ Multiply(c, 0x0B) ^ Multiply(d, 0x0D);
        (*state)[2][i] = Multiply(a, 0x0D) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0E) ^ Multiply(d, 0x0B);
        (*state)[3][i] = Multiply(a, 0x0B) ^ Multiply(b, 0x0D) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0E);
    }
}

static state_t state_save = {0}; // CBC
static bool flag = 1; // CBC
// AES Decryption
void AES_decrypt(const uint8_t *input, uint8_t *output, const unsigned char *mode, uint8_t *iv)
{
    // Initialize the state matrix with input data
    state_t state;
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < Nb; j++) {
            state[j][i] = input[i * Nb + j];
        }
    }

    // AddRoundKey for initial round
    AddRoundKey(Nr, &state);

    // Perform Nr rounds in reverse order for decryption
    for (int round = Nr - 1; round > 0; round--) {
        // Inverse operations for decryption
        InvShiftRows(&state);
        InvSubBytes(&state);
        AddRoundKey(round, &state);
        InvMixColumns(&state);
    }

    // Final round (without InvMixColumns)
    InvShiftRows(&state);
    InvSubBytes(&state);
    AddRoundKey(0, &state); //Nr = 0

    // After decryption, copy the state matrix to the output
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < Nb; j++) {
            output[i * Nb + j] = state[j][i];
        }
    }

    // CBC
    if(strcmp(mode, "CBC") == 0 && flag == 1)
    {
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < Nb; j++) {
                output[i * Nb + j] ^= iv[i * Nb + j]; //iv XOR the final ciphertext block
            }
        }
        flag = 0;
    }
    else if(strcmp(mode, "CBC") == 0)
    {
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < Nb; j++) {
                output[i * Nb + j] ^= state_save[j][i]; //iv XOR the final ciphertext block
            }
        }
    }

    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < Nb; j++) {
            state_save[j][i] = input[i * Nb + j]; //CBC
        }
    }
}
