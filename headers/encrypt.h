#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <string>
#include "global.h"
#include "SHA512.h"
#include "streamcipher.h"

class ENCRYPT
{
    private:
    std::string pass;
    std::string infile;
    std::string outfile;
    bool stdi = false;
    bool stdo = false;
    uint32_t randomArray[SALT_LENGTH_32] = { 0 };
    STREAMCIPHER *sc;
    SHA512 sha512;

    void fillRandomSeedArray(uint32_t *arr, int);

    public:
    ENCRYPT(Options *);
    ~ENCRYPT();
    void combine(char *, int);
    void startEncryption();

};

#endif