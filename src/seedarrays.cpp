#include <fstream>
#include <filesystem>
#include <iostream>

#include "../headers/SHA512.h"
#include "../headers/seedarrays.h"

#if (DEBUG)
    #include <iomanip>
#endif

//class SEEDARRAYS functions
SEEDARRAYS::SEEDARRAYS(Options *o)
{
    #if (DEBUG)
        logfile = new std::fstream;
        logfile->open("logfile.txt", std::ios::out | std::ios::app);
        *logfile << "SFMT_MEXP: " << SFMT_MEXP << "\n";
        *logfile << "SFMT_N: " << SFMT_N << "\n";
        *logfile << "SFMT_N32: " << SFMT_N32 << "\n";
        *logfile << "seed array size: " << (SFMT_N32 * sizeof(uint32_t)) << "\n";
    #endif

    // if password exist -> combine it with seed-arrays
    if(!o->pw.empty()) combineKeyWithSeedArrays(o->pw);

    #if(DEBUG)
        *logfile << "\nSeed 1 after Key: " << "\n";
        printSeedArray(&seed_1);
    #endif

    // if keyfile exist -> read keyfile and combine it with seed-arrays
    if(!o->keyfile.empty()) 
    {
        readKeyfile(o->keyfile);
        addKeyfileToSeedArrays();
    }

    #if(DEBUG)
        *logfile << "\nSeed 1 after Keyfile: " << "\n";
        printSeedArray(&seed_1);
        *logfile << "\nSeed 2 after Keyfile: " << "\n";
        printSeedArray(&seed_2);
    #endif
}

SEEDARRAYS::~SEEDARRAYS()
{
    #if(DEBUG)
        logfile->close();
        delete logfile;
    #endif
}

void SEEDARRAYS::combineSeedArraysWithRandomArray(uint32_t *randomArr, int size)
{
    uint32_t *randomArr_1 = &randomArr[0];
    uint32_t *randomArr_2 = &randomArr[size / 2];
    uint32_t *seedArr_1 = seed_1.getSeed();
    uint32_t *seedArr_2 = seed_2.getSeed();

    for (int i = 0; i < (size / 2); i++)
    {
        seedArr_1[i] ^= randomArr_1[i];
        seedArr_2[i] ^= randomArr_2[i];
    }

    #if(DEBUG)
        *logfile << "\nSeed 1 after Salt: " << "\n";
        printSeedArray(&seed_1);
    #endif
}

//add password to seedArray
void SEEDARRAYS::combineKeyWithSeedArrays(std::string key)
{
    SHA512 sha512;
    HashResult pwHash1, pwHash2;

    sha512.hash512(key, &pwHash1);
    sha512.hash512(pwHash1.digestString, &pwHash2);

    #if(DEBUG)
        *logfile << "\n1st sha512 binary hash of key:\n";
        for(int i = 0; i < 8; i++)
        {
            *logfile << std::setw(16) << std::setfill('0') << std::hex << pwHash1.hashBinary[i] << " ";
            if(!((i + 1) % 8)) *logfile << "\n";
        }
    #endif
    
    addKeyHashToSeed(pwHash1.hashBinary, &seed_1);
    addKeyHashToSeed(pwHash2.hashBinary, &seed_2);
}

void SEEDARRAYS::addKeyHashToSeed(uint64_t *binaryKeyHash, SEED *pSeed)
{
    for (uint i = 0; i < HASH_LEN; i++) pSeed->add64BitValue(binaryKeyHash[i]);
}

//add keyfile to seedArray
int SEEDARRAYS::readKeyfile(std::string keyfileName)
{
    int kfSize = 0;
    int bytesToRead = 0;
    std::ifstream kf;

    kf.open(keyfileName, std::ifstream::binary);

    if(kf.fail())
    {
        std::cerr << "SEEDARRAYS::readKeyfile::Error opening keyfile: " << keyfileName << std::endl;
        exit(EXIT_FAILURE);
    }

    kfSize = std::filesystem::file_size(keyfileName);

    if(kfSize < keyFileLengthMin)
    {
        std::cerr << "SEEDARRAYS::readKeyfile::Keyfile size needs to be at least " << keyFileLengthMin << " bytes." << std::endl;
        kf.close();
        exit(EXIT_FAILURE);
    }

    //make sure to read an even amount from keyfile
    bytesToRead = kfSize - (kfSize % 2);
    bytesToRead = std::min(bytesToRead, keyFileMaxBytes);

    kf.read(keyfileBuffer, bytesToRead);

    if(kf.gcount() != bytesToRead)
    {
        std::cerr << "SEEDARRAYS::readKeyfile::Error reading required bytes from keyfile: " << keyfileName << std::endl;
        kf.close();
        exit(EXIT_FAILURE);
    }

    kf.close();
    keyfileBufferSize = bytesToRead;
    
    return 0;
}

void SEEDARRAYS::addKeyfileToSeedArrays()
{
    int size = keyfileBufferSize / 2;
    combineKeyfileWithSeedArray(&seed_1, &keyfileBuffer[0], size);
    combineKeyfileWithSeedArray(&seed_2, &keyfileBuffer[size], size);
}

void SEEDARRAYS::combineKeyfileWithSeedArray(SEED *seed, char *buffer, int size)
{
    int availableFree = seed->getFree_ch();
    int possible = std::min(availableFree, size);
    
    for (int i = 0; i < possible; i++) seed->addChValue(buffer[i]);
}

uint32_t *SEEDARRAYS::getSeed_1()
{
    return seed_1.getSeed();
}

uint32_t *SEEDARRAYS::getSeed_2()
{
    return seed_2.getSeed();
}

int SEEDARRAYS::getSize_1()
{
    return seed_1.getUsableSize();
}

int SEEDARRAYS::getSize_2()
{
    return seed_2.getUsableSize();
}

#if (DEBUG)
    void SEEDARRAYS::printSeedArray(SEED *seed)
    {
        for(int i = 0; i < SFMT_N32; i++){
            if(!(i % 16)) *logfile << std::setw(4) << std::setfill('0') << std::hex << i << ": ";
            *logfile << std::setw(8) << std::setfill('0') << std::hex << seed->getSeed()[i] << " ";
            if(!((i + 1) % 16)) *logfile << "\n";
        }
        *logfile << "\n";          
    }
#endif

//class SEED functions
int SEED::getFree_ch()
{
	return std::max(0,((SFMT_N32 * 4) - seedArrayIdx_ch));
}

int SEED::getFree_32()
{
	return std::max(0,SFMT_N32 - seedArrayIdx_32);
}

int SEED::getFree_64()
{
	return std::max(0,SFMT_N64 - seedArrayIdx_64);
}

//returns the amount of written 32bit values available inside seedArray
int SEED::getUsableSize()
{
    return seedArrayIdx_32;
}

uint32_t *SEED::getSeed()
{
    return seedArray;
}

void SEED::increaseIdx(int chr_count)
{   
    for (int i = 0; i < chr_count; i++)
    {
        seedArrayIdx_ch ++;
        if ((seedArrayIdx_ch % 4) == 1) seedArrayIdx_32++;
        if ((seedArrayIdx_ch % 8) == 1) seedArrayIdx_64++;
    }
}

void SEED::add64BitValue(uint64_t val)
{
	uint64_t *pSeedArray = nextFreeCell_64();
	
	pSeedArray[0] = val;
	
	increaseIdx(8);
}

void SEED::add32BitValue(uint32_t val)
{
	uint32_t *pSeedArray = nextFreeCell_32();
	
	pSeedArray[0] = val;

	increaseIdx(4);
}

void SEED::addChValue(char val)
{
	char *pSeedArray = nextFreeCell_ch();
	
	pSeedArray[0] = val;
	
	increaseIdx(1);
}

uint32_t *SEED::nextFreeCell_32()
{
	return &seedArray[seedArrayIdx_32];
}

uint64_t *SEED::nextFreeCell_64()
{
	uint64_t *pArr = reinterpret_cast<uint64_t *>(seedArray);
	return &pArr[seedArrayIdx_64];
}

char *SEED::nextFreeCell_ch()
{
	char *pArr = reinterpret_cast<char *>(seedArray);
	return &pArr[seedArrayIdx_ch];
}