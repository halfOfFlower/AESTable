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
#include "aes.h"

extern int _setmode(int, int);
extern uchar Sbox[256];
extern uchar Xtime2[256];
extern uchar in[16];
extern uchar key[16];
extern uchar out[16];

void rd_clock(__int64 *ans){
	unsigned long long dwBoth;

	__asm__ volatile(".byte 0x0f, 0x31" : "=A"(dwBoth));
	*ans = dwBoth;
}

void certify(){
	uchar expkey[4*Nb*(Nr+1)];
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
		printf("%.2x ", out[idx]);
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
	uchar expkey[4*Nb*(Nr+1)];
	FILE *fd = fopen(name, "rb");
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
		while(idx%16){
			in[idx++] = 0;
		}
	}else{
		return;
	}

	Encrypt(in, expkey, out);

	for(idx=0; idx<16; idx++){
		putchar(out[idx]);
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
		case 'c':
			certify();
			break;
		case 'e':
			encrypt(argv[2], argv[3]);
			break;
		case 'd':
			decrypt(argv[2], argv[3]);
			break;
		case 'b':
			bernstein(argv[2]);
			break;
		case 't':
			tables();
			break;
	}

	return 0;
}
