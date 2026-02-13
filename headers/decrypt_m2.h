#ifndef DECRYPT_M2_H
#define DECRYPT_M2_H

#include <string>
#include "global.h"
#include "SHA512.h"
#include "streamcipher.h"

class DECRYPT_M2
{
    private:
    std::string pass;
    std::string infile;
    std::string outfile;
    bool stdi = false;
    bool stdo = false;
    STREAMCIPHER *sc;
    SHA512 sha512;

    public:
    DECRYPT_M2(Options *);
    ~DECRYPT_M2();
    void combineM2(char *, int);
    void startDecryption();

};

#endif
