#include <fstream>

#include "../headers/decrypt_m2.h"

DECRYPT_M2::DECRYPT_M2(Options *o)
{
    infile = o->infile;
    outfile = o->outfile;
    pass = o->pw;
    stdi = o->stdi;
    stdo = o->stdo;
    sc = new STREAMCIPHER(o);
    startDecryption();
}

DECRYPT_M2::~DECRYPT_M2()
{
    delete sc;
}

void DECRYPT_M2::startDecryption()
{
    const int bufferLength = block_size * 2;
    char *ioBuffer = new char[bufferLength];

    //create a new sbox
    sc->createSBox();

    //opening infile/stdin
    std::istream *is;
    if(stdi)
        is = &std::cin;
    else
        is = new std::ifstream(infile, std::ifstream::binary);

    if(is->fail())
    {
        std::cerr << "DECRYPT_M2::startDecryption::Error opening source file: " << infile << std::endl;
        if(!stdi) delete is;
        exit(EXIT_FAILURE);
    }

    //read first 128-byte (encrypted random key) and decrypt
    uint32_t inBuffer[SALT_LENGTH_32] = { 0 };
    is->read(reinterpret_cast<char *>(inBuffer), (sizeof(uint32_t) * SALT_LENGTH_32));
    combineM2(reinterpret_cast<char *>(inBuffer), (sizeof(uint32_t) * SALT_LENGTH_32));

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
        std::cerr << "DECRYPT_M2::startDecryption::Error opening target file: " << outfile << std::endl;
        if(!stdo) delete os;
        exit(EXIT_FAILURE);
    }

    //decrypt file
    int bytesRead;
    while(is->good())
    {
        is->read(ioBuffer, bufferLength);
        bytesRead = is->gcount();
        combineM2(ioBuffer, bytesRead);
        os->write(ioBuffer, bytesRead);
    }

    if(!stdi) delete is;
    if(!stdo) delete os;
    delete [] ioBuffer;
}

void DECRYPT_M2::combineM2(char *buffer, int length)
{
    int stepOneCipher, stepOneInput;
    unsigned char stepTwoCipher, stepTwoTemp;
    uint32_t *pCipherValue;

    //use streamCipher as 32bit blocks
    uint32_t *cipher = reinterpret_cast<uint32_t *>(sc->createStreamCipher());

    #if (DEBUG)
        std::cout << "DECRYPT_M2::combineM2 firts [0] stream cipher uint32: " << cipher[0] << "\n";
    #endif

    for (int i = 0; i < length; i++)
    {
        pCipherValue = &cipher[i];

        //step 1 revert modulo
        stepOneInput = static_cast<unsigned char>(buffer[i]);
        stepOneCipher = static_cast<int>(reinterpret_cast<uint16_t *>(pCipherValue)[1]);
        buffer[i] = static_cast<char>((stepOneInput - stepOneCipher) % 256);

        //step 2 revert rotate
        stepTwoCipher = reinterpret_cast<unsigned char *>(pCipherValue)[1];
        stepTwoTemp = static_cast<unsigned char>(buffer[i]);
        if (stepTwoCipher % 2)
            buffer[i] = static_cast<char>(std::rotr(stepTwoTemp, std::popcount(stepTwoCipher)));
        else
            buffer[i] = static_cast<char>(std::rotl(stepTwoTemp, std::popcount(stepTwoCipher)));

        //step 3 revert XOR
        buffer[i] ^= reinterpret_cast<char *>(pCipherValue)[0];

        //step 4 revert from sbox value
        buffer[i] = sc->revertWithSBox(buffer[i]);
    }
}
