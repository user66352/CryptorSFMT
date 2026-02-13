#include "../headers/streamcipher.h"

STREAMCIPHER::STREAMCIPHER(Options *o)
{
    int arrSize_1 = sfmt_1.minArrSize;
    int arrSize_2 = sfmt_2.minArrSize;
    block_size = std::max(arrSize_1, arrSize_2);

    #if (DEBUG)
        std::cout << "block_size: " << block_size << "\n";
    #endif

    cipherArr_1 = createCipherArray(block_size);
    cipherArr_2 = createCipherArray(block_size);

    streamCipher = new char[sizeof(uint64_t) * block_size];
    pSeedArrays = new SEEDARRAYS(o);

    sfmt_1.seedSFMT(pSeedArrays->getSeed_1(), pSeedArrays->getSize_1());
    sfmt_2.seedSFMT(pSeedArrays->getSeed_2(), pSeedArrays->getSize_2());

    SBox.decryption = o->decrypt;
}

STREAMCIPHER::~STREAMCIPHER()
{
    delete pSeedArrays;
    free(cipherArr_1);
    free(cipherArr_2);
    delete [] streamCipher;
}

uint64_t *STREAMCIPHER::createCipherArray(int size)
{
    uint64_t *array;

    //initialize array for random numbers; platform dependent
    #if defined(__APPLE__) || \
        (defined(__FreeBSD__) && __FreeBSD__ >= 3 && __FreeBSD__ <= 6)
        array = malloc(sizeof(double) * size);
        if (array == NULL) {
        std::cerr << "malloc: can't allocate memory.\n";
        exit(EXIT_FAILURE);
        }
    #elif defined(_POSIX_C_SOURCE)
        if (posix_memalign((void **)&array, 16, sizeof(double) * size) != 0) {
        std::cerr << "posix_memalign: can't allocate memory.\n";
        exit(EXIT_FAILURE);
        }
    #elif defined(__GNUC__) && (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 3))
        array = memalign(16, sizeof(double) * size);
        if (array == NULL) {
        std::cerr << "memalign: can't allocate memory.\n";
        exit(EXIT_FAILURE);
        }
    #else /* in this case, gcc doesn't support SSE2 */
        array = malloc(sizeof(double) * size);
        if (array == NULL) {
        std::cerr << "malloc (no SSE2): can't allocate memory.\n";
        exit(EXIT_FAILURE);
        }
    #endif

    return array;
}

//fill both cipher array's with random numbers
void STREAMCIPHER::fillCipherArrays()
{
    sfmt_1.fillArray(cipherArr_1, block_size);
    sfmt_2.fillArray(cipherArr_2, block_size);
}

//create final streamcipher for encryption/decryption
char *STREAMCIPHER::createStreamCipher()
{
    uint64_t *streamCipher_N64 = reinterpret_cast<uint64_t *>(streamCipher);

    fillCipherArrays();
    for (int i = 0; i < block_size; i++) streamCipher_N64[i] = cipherArr_1[i] ^ cipherArr_2[i];

    return streamCipher;
}

//add random salt to seed arrays's
void STREAMCIPHER::addSalt(uint32_t *salt, int size)
{
    pSeedArrays->combineSeedArraysWithRandomArray(salt, size);
    reseed();
}

//re-seed SFMT's after adding salt to seed array's
void STREAMCIPHER::reseed()
{
    sfmt_1.seedSFMT(pSeedArrays->getSeed_1(), pSeedArrays->getSize_1());
    sfmt_2.seedSFMT(pSeedArrays->getSeed_2(), pSeedArrays->getSize_2());
}


/*
*************
* SBOX CODE *
*************
*/

//creates an SBox for mode 2
void STREAMCIPHER::createSBox()
{
    SBox.cipherByteLength = block_size * sizeof(uint64_t);

    SBox.streamCipher = new uint8_t[block_size * sizeof(uint64_t)];
    fillStreamCipherForSBox(SBox.streamCipher);

    //initiate sbox values
    for (int i = 0; i < 256; i++) SBox.sbox[i] = static_cast<char>(i);
}

//scramble sbox
void STREAMCIPHER::scrambleSBox()
{
    int upperLimit = SBox.usedCipherBytes + (256 * SBOX_SCRAMBLE_ROUNDS);
    char temp_a;
    char temp_b;
    int sbox_idx;

    if (upperLimit >= SBox.cipherByteLength)
    {
        fillStreamCipherForSBox(SBox.streamCipher);
        upperLimit = 8;
    }

    for (int i = SBox.usedCipherBytes; i < upperLimit; i += 2)
    {
        SBox.usedCipherBytes += 2;
        sbox_idx = std::rotl(SBox.streamCipher[i], (int) std::popcount(SBox.streamCipher[i + 1]));
        temp_a = SBox.sbox[i % 256];
        temp_b = SBox.sbox[sbox_idx];
        SBox.sbox[i % 256] = temp_b;
        SBox.sbox[sbox_idx] = temp_a;
    }

    //create invers sbox for decryption
    if(SBox.decryption)
        for (int i = 0; i < 256; i++) SBox.sbox_revers[static_cast<uint8_t>(SBox.sbox[i])] = static_cast<char>(i);
}

void STREAMCIPHER::fillStreamCipherForSBox(uint8_t *pU8Cipher)
{

    #if (DEBUG)
        std::cout << "enter fill streamcipher for sbox\n";
        std::cout << "usedCipherBytes: " << SBox.usedCipherBytes << "\n";
    #endif

    uint64_t *pCipher= reinterpret_cast<uint64_t *>(pU8Cipher);

    fillCipherArrays();
    for (int i = 0; i < block_size; i++) pCipher[i] = cipherArr_1[i] ^ cipherArr_2[i];

    SBox.usedCipherBytes = 0;
}

char STREAMCIPHER::replaceWithSBox(char c)
{
    if(!(SBox.accessCounter % SBOX_SCRAMBLE_INTERVAL)) scrambleSBox();
    SBox.accessCounter++;
    return SBox.sbox[static_cast<uint8_t>(c)];
}

char STREAMCIPHER::revertWithSBox(char c)
{
    if(!(SBox.accessCounter % SBOX_SCRAMBLE_INTERVAL)) scrambleSBox();
    SBox.accessCounter++;
    return SBox.sbox_revers[static_cast<uint8_t>(c)];
}