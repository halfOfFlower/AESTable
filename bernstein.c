#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include "aes.h"
#include "bernstein.h"

extern int _setmode(int, int);
extern uchar Sbox[256];
extern uchar Xtime2[256];

uchar in[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
uchar key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
uchar out[16];

uchar expkey[4*Nb*(Nr+1)];
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

int bestx(int b, int loops){
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

void bernstein(char *seed){
	int loops, b, j, k;

	mrandom(strlen(seed), seed);

	for(loops=4; loops<=65536; loops*=16){
		for(b=0; b<16; b++){
			printf("%.2d, %.5d loops:", b, loops);
			for(k=0; k<10; k++){
				for(j=0; j<16; j++){
					key[j] = xrandom() >> 16;
				}
				ExpandKey(key, expkey);
				printf(" %.2x", bestx(b, loops) ^ key[b]);
				fflush(stdout);
			}
			printf("\n");
		}
	}
}
