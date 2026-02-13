//Encryption Mode 2

#include <bit>
#include <random>
#include <fstream>
#include "../headers/encrypt_m2.h"

ENCRYPT_M2::ENCRYPT_M2(Options *o)
{
    infile = o->infile;
    outfile = o->outfile;
    pass = o->pw;
    stdi = o->stdi;
    stdo = o->stdo;
    sc = new STREAMCIPHER(o);
    startEncryption();
}

ENCRYPT_M2::~ENCRYPT_M2()
{
    delete sc;
}

void ENCRYPT_M2::startEncryption()
{
    //with encryption mode 2 for every 64bit from SFMT we can encrypt 2 bytes from plain text
    int bufferLength = block_size * 2;
    char *ioBuffer = new char[bufferLength];

    //create a new sbox
    sc->createSBox();

	//generate system random data (salt) for encryption
    fillRandomSeedArray(randomArray, SALT_LENGTH_32);

    //write randomArray (salt) to outfile
    //copy salt to outbuffer
    uint32_t outBuffer[SALT_LENGTH_32] = { 0 };
    for (int i = 0; i < SALT_LENGTH_32; i++) outBuffer[i] = randomArray[i];

    //encrypt salt before writing it to disk
    combineM2(reinterpret_cast<char *>(outBuffer), (sizeof(uint32_t) * SALT_LENGTH_32));

    //opening outfile/stdout and write encrypted random salt (outBuffer) at start of outfile
    std::ostream *os;
    if(stdo)
        os = &std::cout;
    else
        os = new std::ofstream(outfile, std::ofstream::binary);

    if(os->fail())
    {
        std::cerr << "ENCRYPT_M2::startEncryption::Error opening target file: " << outfile << std::endl;
        if(!stdo) delete os;
        exit(EXIT_FAILURE);
    }
    os->write(reinterpret_cast<char *>(outBuffer), (sizeof(uint32_t) * SALT_LENGTH_32));

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
        std::cerr << "ENCRYPT_M2::startEncryption::Error opening source file: " << infile << std::endl;
        if(!stdi) delete is;
        exit(EXIT_FAILURE);
    }

    //encrypt file with random seed
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

//takes a pointer to a char array and the length of that array
//than combines that char array with the stream cipher according to Mode 2 (see documentation)
void ENCRYPT_M2::combineM2(char *buffer, int length)
{
    unsigned char stepThreeCipher;
    unsigned char stepThreeTemp;
    uint16_t stepFourCipher;
    uint32_t stepFourTemp;
    uint32_t *pCipherValue;

    //use streamCipher as 32bit blocks
    uint32_t *cipher = reinterpret_cast<uint32_t *>(sc->createStreamCipher());

    #if (DEBUG)
        std::cout << "ENCRYPT_M2::combineM2 first [0] stream cipher uint32: " << cipher[0] << "\n";
    #endif

    for (int i = 0; i < length; i++)
    {
        pCipherValue = &cipher[i];

        //step 1 replace plain text char with value from sbox
        buffer[i] = sc->replaceWithSBox(buffer[i]);

        //step 2 XOR
        buffer[i] ^= reinterpret_cast<char *>(pCipherValue)[0];

        //step 3 rotate
        stepThreeCipher = reinterpret_cast<unsigned char *>(pCipherValue)[1];
        stepThreeTemp = static_cast<unsigned char>(buffer[i]);
        if (stepThreeCipher % 2)
            buffer[i] = static_cast<char>(std::rotl(stepThreeTemp, std::popcount(stepThreeCipher)));
        else
            buffer[i] = static_cast<char>(std::rotr(stepThreeTemp, std::popcount(stepThreeCipher)));

        //step 4 modulo
        stepFourCipher = reinterpret_cast<uint16_t *>(pCipherValue)[1];
        stepFourTemp = stepFourCipher + static_cast<unsigned char>(buffer[i]);
        buffer[i] = static_cast<char>(stepFourTemp % 256);
    }
}

void ENCRYPT_M2::fillRandomSeedArray(uint32_t *arr, int size)
{
    static std::uniform_int_distribution<uint32_t> d(0x00000000, 0xffffffff);
    std::random_device&& rd = std::random_device{};             //system dependent; Default token for random_device is usually /dev/urandom on Linux
    for (int i = 0; i < size; i++) arr[i] = d(rd);              //get 2x512 random bits (32 x 32bit -> 128 byte) from system
}
