#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "aes.h"
#include "encrypt.h"

// S-Box Substitution
// SubBytes: Byte substitution using S-box
void SubBytes(state_t *state) {
    for (int i = 0; i < Nb; ++i) {
        for (int j = 0; j < Nb; ++j) {
            (*state)[i][j] = sbox[(*state)[i][j]];
        }
    }
}

// left Circular Shift (row)
// ShiftRows: Row-wise cyclic shifts
void ShiftRows(state_t *state) {
    uint8_t temp;

    // Shift row 2 by 1 byte to the left
    temp = (*state)[1][0]; //row column
    (*state)[1][0] = (*state)[1][1];
    (*state)[1][1] = (*state)[1][2];
    (*state)[1][2] = (*state)[1][3];
    (*state)[1][3] = temp;

    // Shift row 3 by 2 bytes to the left
    temp = (*state)[2][0];
    (*state)[2][0] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp = (*state)[2][1];
    (*state)[2][1] = (*state)[2][3];
    (*state)[2][3] = temp;

    // Shift row 4 by 3 bytes to the left = Shift row 4 by 1 bytes to the right
    temp = (*state)[3][3];
    (*state)[3][3] = (*state)[3][2];
    (*state)[3][2] = (*state)[3][1];
    (*state)[3][1] = (*state)[3][0];
    (*state)[3][0] = temp;
}

// MixColumns: Column mixing operation
void MixColumns(state_t *state) {
    uint8_t a, b, c, d;
    for (int i = 0; i < Nb; i++) {
        a = (*state)[0][i];
        b = (*state)[1][i];
        c = (*state)[2][i];
        d = (*state)[3][i];

        (*state)[0][i] = Multiply(a, 0x02) ^ Multiply(b, 0x03) ^ c ^ d;
        (*state)[1][i] = a ^ Multiply(b, 0x02) ^ Multiply(c, 0x03) ^ d;
        (*state)[2][i] = a ^ b ^ Multiply(c, 0x02) ^ Multiply(d, 0x03);
        (*state)[3][i] = Multiply(a, 0x03) ^ b ^ c ^ Multiply(d, 0x02);
    }
}

static state_t state_save = {0}; //CBC
static bool flag = 1; //CBC
// AES Encryption
void AES_encrypt(const uint8_t *input, uint8_t *output, const unsigned char *mode, uint8_t * iv) 
{
    // Initialize the state matrix with input data
    state_t state;
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < Nb; j++) {
            state[j][i] = input[i * Nb + j];
        }
    }
    
    // CBC CTR
    if(strcmp(mode, "CBC") == 0 && flag == 1)
    {
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < Nb; j++) {
                state[j][i] ^= iv[i * Nb + j];
            }
        }
        flag = 0;
    }
    else if(strcmp(mode, "CBC") == 0 && state_save != 0)
    {
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < Nb; j++) {
                state[j][i] ^= state_save[j][i];
            }
        }
    }
    else if(strcmp(mode, "CTR") == 0)
    {
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < Nb; j++) {
                state[j][i] = iv[i * Nb + j];
            }
        }
    }

    // AddRoundKey for initial round
    AddRoundKey(0, &state);

    // Perform Nr rounds
    for (int round = 1; round < Nr; round++) {
        SubBytes(&state);
        ShiftRows(&state);
        MixColumns(&state);
        AddRoundKey(round, &state);
    }

    // Final round (without MixColumns)
    SubBytes(&state);
    ShiftRows(&state);
    AddRoundKey(Nr, &state);

    // After encryption, copy the state matrix to the output
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < Nb; j++) {
            output[i * Nb + j] = state[j][i];
        }
    }

    // CBC CTR
    if(strcmp(mode, "CBC") == 0)
    {
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < Nb; j++) {
                state_save[j][i] = state[j][i];
            }
        }
    }
    else if(strcmp(mode, "CTR") == 0)
    {
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < Nb; j++) {
                output[i * Nb + j] ^= input[i * Nb + j];
            }
        }
    }
}
