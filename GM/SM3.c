/*************************************************************************
	> File Name: SM3.c
	> Author: reforever
	> Mail: 1589626444@qq.com
	> Created Time:2020/5/7.16:24
 ************************************************************************/

#include "SM3.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void BiToW(unsigned int Bi[], unsigned int W[]){
    int i;
    unsigned int temp;
    for(i = 0; i <= 15; ++i){
        W[i] = (Bi[4*i] << 24) + (Bi[4*i+1] << 16)
                + (Bi[4*i+2] << 8) + (Bi[4*i+3]);
    }
    for(i = 16; i <= 67; ++i){
        temp = W[i-16] ^ W[i-9] ^ SM3_rot_left32(W[i-3], 15);
        W[i] = SM3_p1(temp) ^ (SM3_rot_left32(W[i-13], 7)) ^ W[i-6];
    }

}

void WToW1(unsigned int W[], unsigned int W1[]){
    int i;
    for(i = 0; i < 64; ++i){
        W1[i] = W[i] ^ W[i+4];
    }

}

void CF(unsigned int W[], unsigned int W1[], unsigned int V[]){
    unsigned int SS1;
    unsigned int SS2;
    unsigned int TT1;
    unsigned int TT2;
    unsigned int A, B, C, D, E, F, G, H;
    unsigned int T = SM3_T1;
    unsigned int FF;
    unsigned int GG;
    int j;

    A = V[0];
    B = V[1];
    C = V[2];
    D = V[3];
    E = V[4];
    F = V[5];
    G = V[6];
    H = V[7];

    for(j = 0; j <= 63; ++j){
        if(j == 0){
            T = SM3_T1;
        } else if(j == 16){
            T = SM3_rot_left32(SM3_T2, 16);
        } else {
            T = SM3_rot_left32(T, 1);
        }
        SS1 = SM3_rot_left32((SM3_rot_left32(A, 12) + E + T), 7);
        SS2 = SS1 ^ SM3_rot_left32(A, 12);
        if(j <= 15){
            FF = SM3_ff0(A, B, C);
        } else {
            FF = SM3_ff1(A, B, C);
        }
        TT1 = FF + D + SS2 + *W1;
        ++W1;
        if(j <= 15) {
            GG = SM3_gg0(E, F, G);
        } else {
            GG = SM3_gg1(E, F, G);
        }
        TT2 = GG + H + SS1 + *W;
        ++W;
        D = C;
        C = SM3_rot_left32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = SM3_rot_left32(F, 19);
        F = E;
        E = SM3_p0(TT2);
        printf("\nA = %x", A);
        printf("  B = %x", B);
        printf("  C = %x", C);
        printf("  D = %x", D);
        printf("  E = %x", E);
        printf("  F = %x", F);
        printf("  G = %x", G);
        printf("  H = %x", H);
    }

    V[0] = A ^ V[0];
    V[1] = B ^ V[1];
    V[2] = C ^ V[2];
    V[3] = D ^ V[3];
    V[4] = E ^ V[4];
    V[5] = F ^ V[5];
    V[6] = G ^ V[6];
    V[7] = H ^ V[7];
    printf("\nV[0] = %x\n", V[0]);
    printf("V[1] = %x\n", V[1]);
    printf("V[2] = %x\n", V[2]);
    printf("V[3] = %x\n", V[3]);
    printf("V[4] = %x\n", V[4]);
    printf("V[5] = %x\n", V[5]);
    printf("V[6] = %x\n", V[6]);
    printf("V[7] = %x\n\n", V[7]);
}

void SM3_compress(SM3_STATE * md){
    unsigned int W[68];
    unsigned int W1[64];
    printf("\n");
    BiToW(md->buf, W);
    for(int j = 0; j < 68; ++j){
        printf("%x ", W[j]);
    }
    printf("-------------------\n");
    WToW1(W, W1);
    for(int j = 0; j < 64; ++j){
        printf("%x ", W1[j]);
    }
    CF(W, W1, md->state);
}

void SM3_process(SM3_STATE * md, unsigned char buf[], int len){
    while(len--){
        md->buf[md->curlen] = *buf++;
        md->curlen++;
        // 每64 * 8 = 512位分一次块
        if(md->curlen == 64){
            SM3_compress(md);
            md->length += 512;
            md->curlen = 0;
        }
    }
}

void SM3_init(SM3_STATE * md){
    memset(md->buf, 0, sizeof(md->buf));
    md->curlen = 0;
    md->length = 0;
    md->state[0] = SM3_IVA;
    md->state[1] = SM3_IVB;
    md->state[2] = SM3_IVC;
    md->state[3] = SM3_IVD;
    md->state[4] = SM3_IVE;
    md->state[5] = SM3_IVF;
    md->state[6] = SM3_IVG;
    md->state[7] = SM3_IVH;
}

void SM3_done(SM3_STATE *md, unsigned char hash[])
{
    int i;
    unsigned char tmp = 0;
    md->length += md->curlen <<3;
    //printf("%d\n", md->length);
    md->buf[md->curlen] = 0x80;
    md->curlen++;
    if (md->curlen > 56) {
        while(md->curlen < 64) {
            md->buf[md->curlen] = 0;
            md->curlen++;
        }
        SM3_compress(md);
        md->curlen = 0;
    }
    while (md->curlen < 56){
        md->buf[md->curlen] = 0;
        md->curlen++;
    }
    for (i = 56; i < 60; i++){
        md->buf[i] = 0;
    }
    md->buf[63] = md->length & 0xff;
    md->buf[62] = (md->length >> 8) & 0xff;
    md->buf[61] = (md->length >> 16) & 0xff;
    md->buf[60] = (md->length >> 24) & 0xff;
    for(int j = 0; j < 64; ++j){
        printf("%x ", md->buf[j]);
    }
    SM3_compress(md);
    printf("\nmd->state[0] = %x\n", md->state[0]);
    printf("md->state[1] = %x\n", md->state[1]);
    printf("md->state[2] = %x\n", md->state[2]);
    printf("md->state[3] = %x\n", md->state[3]);
    printf("md->state[4] = %x\n", md->state[4]);
    printf("md->state[5] = %x\n", md->state[5]);
    printf("md->state[6] = %x\n", md->state[6]);
    printf("md->state[7] = %x\n", md->state[7]);
    printf("sizeof(md->state) = %d\n", sizeof(md->state));
    //memcpy(hash, md->state, SM3_len/8);
    int temp = 0;
    for(i = 0; i < 8; ++i) {
        temp += sprintf(hash + temp, "%x", md->state[i]);
    }
}

void SM3_256(unsigned char buf[], int len, unsigned char hash[]){
    SM3_STATE md;
    SM3_init(&md);
    SM3_process(&md, buf, len);
    SM3_done(&md, hash);
    printf("hash = %s\n", hash);
}
