#ifndef ENCRYPT_M2_H
#define ENCRYPT_M2_H

#include <string>
#include "global.h"
#include "SHA512.h"
#include "streamcipher.h"

class ENCRYPT_M2
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
    ENCRYPT_M2(Options *);
    ~ENCRYPT_M2();
    void combineM2(char *, int);
    void startEncryption();

};

#endif