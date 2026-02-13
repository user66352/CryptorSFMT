#ifndef SEEDARRAYS_H
#define SEEDARRAYS_H

#include <iostream>
#include "global.h"
#include "SFMT.h"

class SEED
{
	private:
		int seedArrayIdx_32 = 0;
		int seedArrayIdx_64 = 0;
		int seedArrayIdx_ch = 0;
		uint32_t seedArray[SFMT_N32] = { 0 };
		
		uint32_t *nextFreeCell_32();
		uint64_t *nextFreeCell_64();
		char *nextFreeCell_ch();
		void increaseIdx(int);

	public:
		int getFree_64();
		int getFree_32();
		int getFree_ch();
        int getUsableSize();
        uint32_t *getSeed();
		void add64BitValue(uint64_t);
		void add32BitValue(uint32_t);
		void addChValue(char);
};

class SEEDARRAYS
{
    private:
    SEED seed_1;
    SEED seed_2;
    int keyfileBufferSize = 0;
    char keyfileBuffer[keyFileMaxBytes] = { 0 };

	#if (DEBUG)
		std::fstream *logfile;
		void printSeedArray(SEED *);
	#endif
	
    int readKeyfile(std::string);
    void addKeyfileToSeedArrays();
    void combineKeyfileWithSeedArray(SEED *, char *, int);
    void combineKeyWithSeedArrays(std::string);
    void addKeyHashToSeed(uint64_t *, SEED *);
   
    public:
    SEEDARRAYS(Options *);
	~SEEDARRAYS();
    void combineSeedArraysWithRandomArray(uint32_t *, int);
	uint32_t *getSeed_1();
	uint32_t *getSeed_2();
	int getSize_1();
	int getSize_2();
};

#endif