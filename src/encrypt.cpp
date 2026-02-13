//Encryption Mode 1

#include <random>
#include <fstream>
#include "../headers/encrypt.h"

ENCRYPT::ENCRYPT(Options *o)
{
    infile = o->infile;
    outfile = o->outfile;
    pass = o->pw;
    stdi = o->stdi;
    stdo = o->stdo;
    sc = new STREAMCIPHER(o);
    startEncryption();
}

ENCRYPT::~ENCRYPT()
{
    delete sc;
}

void ENCRYPT::startEncryption()
{
    int bufferLength = block_size * sizeof(uint64_t);
    char *ioBuffer = new char[bufferLength];

	//generate system random data (salt) for encryption
    fillRandomSeedArray(randomArray, SALT_LENGTH_32);

    //write randomArray (salt) to outfile
    //copy salt to outbuffer
    uint32_t outBuffer[SALT_LENGTH_32] = { 0 };
    for (int i = 0; i < 32; i++) outBuffer[i] = randomArray[i];

    //encrypt salt before writing it to disk
    combine(reinterpret_cast<char *>(outBuffer), (4 * SALT_LENGTH_32));

    //opening outfile/stdout and write encrypted random salt (outBuffer) at start of outfile
    std::ostream *os;
    if(stdo)
        os = &std::cout;
    else
        os = new std::ofstream(outfile, std::ofstream::binary);

    if(os->fail())
    {
        std::cerr << "ENCRYPT::startEncryption::Error opening target file: " << outfile << std::endl;
        if(!stdo) delete os;
        exit(EXIT_FAILURE);
    }
    os->write(reinterpret_cast<char *>(outBuffer), (4 * SALT_LENGTH_32));

    //combine random bytes with SFMT seed's
    sc->addSalt(randomArray, SALT_LENGTH_32);

    //opening infile/stdin
    std::istream *is;
    if(stdi)
        is = &std::cin;
    else
        is = new std::ifstream(infile, std::ifstream::binary);

    if(is->fail())
    {
        std::cerr << "ENCRYPT::startEncryption::Error opening source file: " << infile << std::endl;
        if(!stdi) delete is;
        exit(EXIT_FAILURE);
    }

    //encrypt file with random seed
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

void ENCRYPT::combine(char * buffer, int length)
{
    char *cipher = sc->createStreamCipher();
    for(int i = 0; i < length; i++) buffer[i] ^= cipher[i];
}

void ENCRYPT::fillRandomSeedArray(uint32_t *arr, int size)
{
    static std::uniform_int_distribution<uint32_t> d(0x00000000, 0xffffffff);
    std::random_device&& rd = std::random_device{};             //system dependent; Default token for random_device is usually /dev/urandom on Linux
    for (int i = 0; i < size; i++) arr[i] =  d(rd);             //get 2x512 random bits (32 x 32bit -> 128 byte) from system
}
