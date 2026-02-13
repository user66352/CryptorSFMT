#ifndef DECRYPT_H
#define DECRYPT_H

#include <string>
#include "global.h"
#include "SHA512.h"
#include "streamcipher.h"

class DECRYPT
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
    DECRYPT(Options *);
    ~DECRYPT();
    void combine(char *, int);
    void startDecryption();

};

#endif
