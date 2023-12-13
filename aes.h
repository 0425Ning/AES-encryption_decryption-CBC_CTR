#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define Nb 4
#define Nk 4 // keysize / 32, keysize = 128 in this case
#define Nr 10 // Nr = Nk + 6
#define BLOCK_SIZE 16 // AES block size in bytes
#define ROUNDKEY_SIZE 176 // BLOCK_SIZE * (Nr+1)
#define STATE_DIMENSION 4
#define BOX_SIZE 256
#define RCON_SIZE 11

// AES Round Keys
unsigned char RoundKey[ROUNDKEY_SIZE]; // round key array, stored Main Key and Expanded Key (Ex: AES-128(44words/176 bytes), AES-256(60w/260bytes)), store the array of main key and expansion key, w0(index 0 ~ 3) w1(index 4 ~ 7)....

// temp state array in encrypt state, Status array during encryption operation 4 * 4 
typedef uint8_t state_t[STATE_DIMENSION][STATE_DIMENSION];

// AES S-box
static const uint8_t sbox[BOX_SIZE] =   
{
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  //F
};

// Inverse S-box
static const uint8_t inv_sbox[BOX_SIZE] =   
{
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
};

/**
 *  xtime macro: (input * {02}) mod {1b}  GF(2^8)
 *  02 = x = 00000010(binary) over GF(2^8)
 *  1b = x^8 + x^4 + x^3 + x^1 + 1 = 00011011(binary) over GF(2^8) 
 *  
 *  
 *  (x << 1) -- present input * {02}  = shift 1 bit
 *  (x >> 7) -- input / 2^7, It means only taking the 8th bit
 *  ((x >> 7) & 1) * 0x1b ----
 * 
 *  If the 8th bit is 1, it means that there will be remainder after mod(2^7) => 00011011,
 *  Finally, the whole xtime(x) become (x << 1) xor 00011011 (For details, please see GF(2^n) fast mod operation method)
 * 
 *  If the 8th bit is 0, it will become 0 * 0x1b,
 *  Finally, the whole xtime(x) (x << 1) XOR 0 = (x << 1)
 */
#define xtime(x)   ((x << 1) ^ (((x >> 7) & 1) * 0x1b)) // Define the xtime macro

/** Multiplty macro: (x * y) mod GF(2^8)
 *  (y & 0x01) * x) Represents the first (rightmost) bit. If it is 1, it is input-x. If it is 0, it represents 0 (XOR with no effect)
 *  ((y >> 1 & 0x01) * xtime(x)) Represents that if the second bit is 1, the result is input * {02}. If it is 0, the result would be represents 0 (no impact on XOR)
 *  ...Similarly
 *  Because the inverse matrix constant can be up to 14 (which can be represented by 4 bits), it can be done (y >> 4 & 0x01)
 */
#define Multiply(x,y)   ((y      & 0x01) * x) \
                      ^ ((y >> 1 & 0x01) * xtime(x)) \
                      ^ ((y >> 2 & 0x01) * xtime(xtime(x))) \
                      ^ ((y >> 3 & 0x01) * xtime(xtime(xtime(x)))) \
                      ^ ((y >> 4 & 0x01) * xtime(xtime(xtime(xtime(x)))))
//unsigned char multiply(unsigned char, unsigned char);

/**
 * Rcon used in KeyExpansion
 * this Rcon table can gernerate from GF(2^8)
 * Rcon[0] will not be used(Easy to code), set any redundant num
 * AES uses up to rcon[10] for AES-128 (as 11 round keys are needed), up to rcon[8] for AES-192, and up to rcon[7] for AES-256.
 */
static const uint8_t Rcon[RCON_SIZE] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
}; // AES Round Constants

/** Key Expansion function, to generate all keys
 *  Input: Key[](main key), Nr(round), Nb, Nb_k(AES-128(4 block), AES-192(6), AES-256(8))
 *  Output: Roundkey[], generate all subkeys - AES-128(44), 192(52), 256(60), 
 */
void KeyExpansion(const uint8_t *, uint8_t *);

/**
 *  Cipher() AES encrypt function
 *  Input: in[16] plaintext block(128 bits), Nr (Number of round), Key[]
 *  output: out[16] cipher block(128 bits), 
 */
void AddRoundKey(int, state_t *);