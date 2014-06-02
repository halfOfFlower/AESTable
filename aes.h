#include <string.h>
#include <memory.h>

typedef unsigned char uchar;

#ifdef __unix__
        typedef long __int64;
#endif

#define Nb 4			// number of columns in the state & expanded key
#define Nk 4			// number of columns in a key
#define Nr 10			// number of rounds in encryption

void ShiftRows(uchar *);
void InvShiftRows(uchar *);
void MixSubColumns(uchar *);
void InvMixSubColumns(uchar *);
void AddRoundKey(unsigned *, unsigned *);
void ExpandKey(uchar *, uchar *);
void Encrypt(uchar *, uchar *, uchar *);
void Decrypt(uchar *, uchar *, uchar *);
