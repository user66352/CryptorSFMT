#include "../headers/sfmtrng.h"

SFMTRNG::SFMTRNG()
{
    minArrSize = sfmt_get_min_array_size64(&sfmt);
}

void SFMTRNG::seedSFMT(uint32_t *seedArray, int size)
{
    sfmt_init_by_array(&sfmt, seedArray, size);
}

void SFMTRNG::fillArray(uint64_t *array, int size)
{
    sfmt_fill_array64(&sfmt, array, size);
}