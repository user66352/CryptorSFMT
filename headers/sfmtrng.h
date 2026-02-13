#ifndef SFMTRNG_H
#define SFMTRNG_H

#include "global.h"
#include "SFMT.h"

class SFMTRNG
{
    private:
    sfmt_t sfmt;

    public:
    int minArrSize;
    
    SFMTRNG();
    void seedSFMT(uint32_t *seedArray, int size);
    void fillArray(uint64_t *, int);

};

#endif