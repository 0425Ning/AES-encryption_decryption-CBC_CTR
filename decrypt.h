#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

// Inverse S-Box Substitution
void InvSubBytes(state_t *);

// right(inverse) Circular Shift (row)
void InvShiftRows(state_t *);

/** InvMixColumns() is a Mixed row operation functions 
 * 
 *  Execute 4 times (4 subblock). Each column is executed as follows:
 *  b0     [14 11 13  9   [d0  
 *  b1       9 14 11 13    d1
 *  b2  =   13  9 14 11    d2
 *  b3      11 13  9 14]   d3]
 */
void InvMixColumns(state_t *);

void AES_decrypt(const uint8_t *, uint8_t *, const unsigned char *, uint8_t *);