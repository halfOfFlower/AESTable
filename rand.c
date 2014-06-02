/*
 * The package generates far better random numbers than a linear
 * congruential generator.  The random number generation technique
 * is a linear feedback shift register approach.  In this approach,
 * the least significant bit of all the numbers in the RandTbl table
 * will act as a linear feedback shift register, and will have period
 * of approximately 2^96 - 1.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define RAND_order (7 * sizeof(unsigned))
#define RAND_size (96 * sizeof(unsigned))

unsigned char RandTbl[RAND_size + RAND_order];
int RandHead = 0;

/*
 * random: 	x**96 + x**7 + x**6 + x**4 + x**3 + x**2 + 1
 *
 * The basic operation is to add to the number at the head index
 * the XOR sum of the lower order terms in the polynomial.
 * Then the index is advanced to the next location cyclically
 * in the table.  The value returned is the sum generated.
 *
 */

unsigned xrandom(){
	register unsigned fact;

	if((RandHead -= sizeof(unsigned))<0){
		RandHead = RAND_size - sizeof(unsigned);
		memcpy(RandTbl + RAND_size, RandTbl, RAND_order);
	}

	fact = *(unsigned *)(RandTbl + RandHead + 7 * sizeof(unsigned));
	fact ^= *(unsigned *)(RandTbl + RandHead + 6 * sizeof(unsigned));
	fact ^= *(unsigned *)(RandTbl + RandHead + 4 * sizeof(unsigned));
	fact ^= *(unsigned *)(RandTbl + RandHead + 3 * sizeof(unsigned));
	fact ^= *(unsigned *)(RandTbl + RandHead + 2 * sizeof(unsigned));
	return *(unsigned *)(RandTbl + RandHead) += fact;
}

/*
 * mrandom:
 *
 * Initialize the random number generator based on the given seed.
 *
 */
void mrandom(int len, char *ptr){
	unsigned short rand = *ptr;
	int idx, bit = len * 4;

	memset(RandTbl, 0, sizeof(RandTbl));
	RandHead = 0;

	while(rand *= 20077, rand += 11, bit--){
		if(ptr[bit>>2] & (1<<(bit & 3))){
			for(idx = 0; idx<5; idx++){
				rand *= 20077, rand += 11;
				RandTbl[rand % 96 << 2] ^= 1;
			}
		}
	}

	for(idx=0; idx<96*63; idx++){
		xrandom ();
	}
}
