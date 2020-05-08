/*************************************************************************
	> File Name: SM3.h
	> Author: reforever
	> Mail: 1589626444@qq.com
	> Created Time:2020/5/7.16:24

 Function List:
 1.SM3_256 //calls SM3_init, SM3_process and SM3_done to calculate hash value
 2.SM3_init //init the SM3 state
 3.SM3_process //compress the the first len/64 blocks of the message
 4.SM3_done //compress the rest message and output the hash value
 5.SM3_compress //called by SM3_process and SM3_done, compress a single block of message
 6.BiToW //called by SM3_compress,to calculate W from Bi
 7.WToW1 //called by SM3_compress, calculate W' from W
 8.CF //called by SM3_compress, to calculate CF function.
 ************************************************************************/

#ifndef GM_SM3_H
#define GM_SM3_H
#define SM3_len 256
#define SM3_T1 0x79CC4519
#define SM3_T2 0x7A879D8A
#define SM3_IVA 0x7380166f
#define SM3_IVB 0x4914b2b9
#define SM3_IVC 0x172442d7
#define SM3_IVD 0xda8a0600
#define SM3_IVE 0xa96f30bc
#define SM3_IVF 0x163138aa
#define SM3_IVG 0xe38dee4d
#define SM3_IVH 0xb0fb0e4e
#define SM3_p1(x) (x ^ SM3_rot_left32(x, 15) ^ SM3_rot_left32(x, 23))
#define SM3_p0(x) (x ^ SM3_rot_left32(x, 9) ^ SM3_rot_left32(x, 17))
#define SM3_ff0(a,b,c) (a^b^c)
#define SM3_ff1(a,b,c) ((a&b)|(a&c)|(b&c))
#define SM3_gg0(e,f,g) (e^f^g)
#define SM3_gg1(e,f,g) ((e&f)|((~e)&g))
#define SM3_rot_left32(x,n) ((((unsigned int) x) << n) | (((unsigned int) x) >> (32 - n)))
#define SM3_rot_right32(x,n) ((((unsigned int) x) >> n) | (((unsigned int) x) << (32 - n)))

typedef struct {
    unsigned int state[8];
    unsigned int length;
    unsigned int curlen;
    unsigned int buf[64];
} SM3_STATE;

void BiToW(unsigned int Bi[], unsigned int Wj[]);
void WToW1(unsigned int Wj[], unsigned int Wj1[]);
void CF(unsigned int Wj[], unsigned int Wj1[], unsigned int V[]);
void SM3_init(SM3_STATE *md);
void SM3_compress(SM3_STATE * md);
void SM3_process(SM3_STATE * md, unsigned char buf[], int len);
void SM3_done(SM3_STATE *md, unsigned char *hash);
void SM3_256(unsigned char buf[], int len, unsigned char hash[]);

#endif //GM_SM3_H
