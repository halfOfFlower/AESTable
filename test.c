/*
 * Dinux Copyright 2009
 *
 * Minimal AES implementation
 * Using static predefined tables
 *
 * Code cannot be used in a production libraries
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include "aestable.h"

extern int _setmode (int, int);
extern uchar Sbox[256];
extern uchar Xtime2[256];

uchar in[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
uchar key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
uchar out[16];

#ifdef __unix__
	typedef long __int64;
#endif

void rd_clock(__int64 *ans){
	unsigned long long dwBoth;

	__asm__ volatile(".byte 0x0f, 0x31" : "=A"(dwBoth));
	*ans = dwBoth;
}

void certify(){
	uchar expkey[4 * Nb * (Nr + 1)];
	unsigned idx, diff;
	__int64 start, stop;

	ExpandKey(key, expkey);
	Encrypt(in, expkey, out);

	rd_clock(&start);

	Encrypt(in, expkey, out);

	rd_clock(&stop);
	diff = (stop - start);
	printf("encrypt time: %d, %d cycles per byte\n", diff, diff/16);

	for(idx=0; idx<16; idx++){
		printf ("%.2x ", out[idx]);
	}

	printf("\n");
	Decrypt(out, expkey, in);
	rd_clock(&start);
	Decrypt(out, expkey, in);

	rd_clock(&stop);
	diff = (stop - start);
	printf("decrypt time: %d, %d cycles per byte\n", diff, diff/16);

	for(idx=0; idx<16; idx++){
		printf ("%.2x ", in[idx]);
	}

	printf ("\n");
}

void decrypt(char *mykey, char *name){
	uchar expkey[4 * Nb * (Nr + 1)];
	FILE *fd = fopen (name, "rb");
	int ch, idx = 0;

	strncpy (key, mykey, sizeof(key));
	ExpandKey (key, expkey);

	while(ch = getc(fd), ch != EOF){
		in[idx++] = ch;
		if(idx%16){
			continue;
		}

		Decrypt(in, expkey, out);

		for(idx=0; idx<16; idx++){
			putchar(out[idx]);
		}
		idx = 0;
	}
}

void encrypt(char *mykey, char *name){
	uchar expkey[4 * Nb * (Nr + 1)];
	FILE *fd = fopen (name, "rb");
	int ch, idx = 0;

	strncpy(key, mykey, sizeof(key));
	ExpandKey(key, expkey);

	while(ch = getc(fd), ch != EOF){
		in[idx++] = ch;
		if(idx%16){
			continue;
		}

		Encrypt(in, expkey, out);

		for(idx = 0; idx<16; idx++){
			putchar (out[idx]);
		}
		idx = 0;
	}

	if(idx){
		while(idx % 16){
			in[idx++] = 0;
		}
	}else{
		return;
	}

	Encrypt(in, expkey, out);

	for(idx=0; idx<16; idx++){
		putchar (out[idx]);
	}
}

uchar expkey[4 * Nb * (Nr + 1)];
void mrandom(int, char *);
unsigned xrandom(void);

int aescycles(){
	__int64 start, end;
	int t;

	do{
		rd_clock(&start);
		Encrypt(in, expkey, out);
		rd_clock(&end);
		t = (end - start);
	}while(t<=0 || t>=4000);

	return t;
}

int bestx (int b, int loops){
	int bestx = 0, bestxt = 0;
	int x, xt, i, j;

	for(x=0; x<256; x++){
		xt = 0;
		for(i=0; i<loops; i++){
			for(j=0; j<16; j++){
				in[j] = xrandom() >> 16;
			}
			in[b] = x;
			xt += aescycles(); xt += aescycles(); xt += aescycles();
			xt += aescycles(); xt += aescycles();
		}
		if(xt>bestxt){
			bestx = x, bestxt = xt;
		}
	}
	return bestx;
}

void bernstein (char *seed){
	int loops, b, j, k;

	mrandom(strlen(seed), seed);

	for(loops=4; loops<=65536; loops*=16){
		for(b=0; b<16; b++){
			printf ("%.2d, %.5d loops:", b, loops);
			for(k=0; k<10; k++){
				for(j=0; j<16; j++){
					key[j] = xrandom() >> 16;
				}
				ExpandKey (key, expkey);
				printf(" %.2x", bestx (b, loops) ^ key[b]);
				fflush(stdout);
			}
			printf ("\n");
		}
	}
}

void tables(){
	int i;

	for(i=0; i<256; i++){
		printf("0x%.2x, ", Sbox[i] ^ Xtime2[Sbox[i]]);
		if(!((i+1)%16)){
			printf("\n");
		}
	}

	printf("\n");

	for(i=0; i<256; i++){
		printf("0x%.2x, ", Xtime2[Sbox[i]]);
		if(!((i+1)%16)){
			printf("\n");
		}
	}
}

int main(int argc, char *argv[]){
	if(argc<2){
		printf("Need param\n");
		return 0;
	}
	switch(argv[1][0]){
		case 'c': certify(); break;
		case 'e': encrypt(argv[2], argv[3]); break;
		case 'd': decrypt(argv[2], argv[3]); break;
		case 'b': bernstein(argv[2]);	break;
		case 't': tables(); break;
	}

	return 0;
}

/*
 * The package generates far better random numbers than a linear
 * congruential generator.  The random number generation technique
 * is a linear feedback shift register approach.  In this approach,
 * the least significant bit of all the numbers in the RandTbl table
 * will act as a linear feedback shift register, and will have period
 * of approximately 2^96 - 1.
 *
 */

#define RAND_order (7 * sizeof(unsigned))
#define RAND_size (96 * sizeof(unsigned))

uchar RandTbl[RAND_size + RAND_order];
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

unsigned xrandom (){
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
 * 		Initialize the random number generator based on the given seed.
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
