#include <fstream>

#include "../headers/decrypt.h"

DECRYPT::DECRYPT(Options *o)
{
    infile = o->infile;
    outfile = o->outfile;
    pass = o->pw;
    stdi = o->stdi;
    stdo = o->stdo;
    sc = new STREAMCIPHER(o);
    startDecryption();
}

DECRYPT::~DECRYPT()
{
    delete sc;
}

void DECRYPT::startDecryption()
{
    const int bufferLength = block_size * sizeof(uint64_t);
    char *ioBuffer = new char[bufferLength];

    //opening infile/stdin
    std::istream *is;
    if(stdi)
        is = &std::cin;
    else
        is = new std::ifstream(infile, std::ifstream::binary);

    if(is->fail())
    {
        std::cerr << "Error opening source file: " << infile << std::endl;
        if(!stdi) delete is;
        exit(EXIT_FAILURE);
    }

    //read first 128-byte (encrypted random key) and decrypt
    uint32_t inBuffer[SALT_LENGTH_32] = { 0 };
    is->read(reinterpret_cast<char *>(inBuffer), (4 * SALT_LENGTH_32));
    combine(reinterpret_cast<char *>(inBuffer), (4 * SALT_LENGTH_32));

    //combine random bytes from salt with SFMT seed's
    sc->addSalt(inBuffer, SALT_LENGTH_32);

    //opening outfile/stdout
    std::ostream *os;
    if(stdo)
        os = &std::cout;
    else
        os = new std::ofstream(outfile, std::ofstream::binary);

    if(os->fail())
    {
        std::cerr << "Error opening target file: " << outfile << std::endl;
        if(!stdo) delete os;
        exit(EXIT_FAILURE);
    }

    //decrypt file
    int bytesRead;
    while(is->good())
    {
        bytesRead = 0;
        is->read(ioBuffer, bufferLength);
        bytesRead = is->gcount();
        combine(ioBuffer, bytesRead);
        os->write(ioBuffer, bytesRead);
    }

    if(!stdi) delete is;
    if(!stdo) delete os;
    delete [] ioBuffer;
}

void DECRYPT::combine(char *buffer, int length)
{
    char *cipher = sc->createStreamCipher();
    for(int i = 0; i < length; i++) buffer[i] ^= cipher[i];
}
