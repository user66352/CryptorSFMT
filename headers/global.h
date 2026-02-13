#ifndef GLOBAL_H
#define GLOBAL_H

#include <string>
#include "SFMT.h"

#define DEBUG 0
#define SBOX_SCRAMBLE_ROUNDS 4                      //number of rounds the sbox is scrambled when calling STREAMCIPHER::scrambleSBox()
#define SBOX_SCRAMBLE_INTERVAL 256               //number of characters substituted with the sbox before that sbox is scrambled again

const int SALT_LENGTH_32 = 32;
const int maxPasswordLength = 64;
const int keyFileLengthMin = 8;
const int keyFileMaxBytes = SFMT_N32 * sizeof(uint32_t) * 2;       //each seed receives half the bytes from keyfile
extern int block_size;                                             //stores the amount of random 64bit values created at once

struct Options {
    std::string infile = "";
    std::string outfile = "";
    std::string keyfile = "";
    std::string pw = "";
    std::string mode = "1";
    bool help = false;
    bool version = false;
    bool encrypt = false;
    bool decrypt = false;
    bool stdi = false;
    bool stdo = false;
};

#endif
