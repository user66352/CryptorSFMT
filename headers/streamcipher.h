#ifndef STREAMCYPHER_H
#define STREAMCYPHER_H

#include "global.h"
#include "sfmtrng.h"
#include "seedarrays.h"

struct SBOX
{
    char sbox[256];
    char sbox_revers[256];
    uint8_t *streamCipher;
    uint32_t accessCounter = 0;
    int usedCipherBytes = 0;
    int cipherByteLength;
    bool decryption = false;
};

class STREAMCIPHER
{
    private:
    SFMTRNG sfmt_1;
    SFMTRNG sfmt_2;
    SBOX SBox;
    SEEDARRAYS *pSeedArrays;
    uint64_t *cipherArr_1;
    uint64_t *cipherArr_2;
    char *streamCipher;

    void reseed();
    void fillCipherArrays();
    uint64_t *createCipherArray(int);
    void fillStreamCipherForSBox(uint8_t *);
    void scrambleSBox();

    public:
    STREAMCIPHER(Options *);
    ~STREAMCIPHER();
    char *createStreamCipher();
    void addSalt(uint32_t *, int);
    void createSBox();
    char replaceWithSBox(char);
    char revertWithSBox(char);
};

#endif