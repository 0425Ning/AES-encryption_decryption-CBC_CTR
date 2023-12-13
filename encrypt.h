#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// S-Box Substitution
void SubBytes(state_t *);

// left Circular Shift (row)
void ShiftRows(state_t *);

/** 
 *  MixColumns() is a Mixed row operation functions 
 *  Execute 4 times (4 subblock). Each column is executed as follows:
 *  c0     [2 3 1 1   [b0  
 *  c1      1 2 3 1    b1
 *  c2  =   1 1 2 3    b2
 *  c3      3 1 1 2]   b3]
 * 
 * This is a linear transform
 */
void MixColumns(state_t *);

/**
 * Call Encrypt  function, encrypt one block (128 bit) once
 * input: in[](plaintext), Key[](key)
 * output: out[](cipher) 
 */
void AES_encrypt(const uint8_t *, uint8_t *, const unsigned char *, uint8_t * );