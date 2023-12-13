#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "aes.h"

// KeyExpansion function for round key generation
void KeyExpansion(const uint8_t *key, uint8_t *RoundKey) { /*, int key_length*/
    int i, j;
    uint8_t temp[4], k;

    // The first round key is the original key
    for (i = 0; i < Nk; i++) {
        for (j = 0; j < Nk; j++)
        {
            RoundKey[(i * Nk) + j] = key[(i * Nk) + j];
        }
    }

    for (i = Nk; i < Nb * (Nr + 1); ++i) {
        for (j = 0; j < 4; j++)
            temp[j] = RoundKey[(i - 1) * 4 + j];
        
        if (i % Nk == 0) {
            // RotWord and SubWord operations
            k = temp[0];
            temp[0] = sbox[temp[1]];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[k];

            // XOR with Rcon
            temp[0] ^= Rcon[i / Nk - 1];
        }
        else if (Nk == 8 && i % Nk == 4){
            // Only AES-256 used,
            // When i mod 4 = 0 and i mod 8 ≠ 0, Wn = SubWord (Wn−1) XOR Wn−8
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
        }

        /**
         * Wn = Wn-1 XOR Wk    k = current word - Nb_k
         * Ex: AES-128   Nb_k = 4  when W5 = Wn-1(W4) XOR Wk(W1)
         * Ex: AES-256   Nb_k = 8  when W10 = Wn-1(W9) XOR Wk(W2) 
         */
        // XOR operation
        RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ temp[0];
        RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ temp[1];
        RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ temp[2];
        RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ temp[3];
    }
    
    return;
}

// AddRoundKey: XOR state with round key
void AddRoundKey(int round, state_t *state) {
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < Nb; ++j) {
            //(*state)[i][j] ^= RoundKey[round * Nb * Nb + i * Nb + j];
            (*state)[j][i] ^= RoundKey[round * Nb * Nb + (i * Nb + j)];
        }
    }
}