/*************************************************************************
	> File Name: SM3.c
	> Author: reforever
	> Mail: 1589626444@qq.com
	> Created Time:2020/5/7.16:24
 ************************************************************************/

#include "SM3.h"
#include <string.h>
#include <stdio.h>


void BiToW(const unsigned int Bi[], unsigned int W[]) {
    int i;
    unsigned int temp;
    for(i = 0; i <= 15; ++i){
        W[i] = (Bi[4*i] << 24u) + (Bi[4*i+1] << 16u)
               + (Bi[4*i+2] << 8u) + (Bi[4*i+3]);
    }
    for(i = 16; i <= 67; ++i){
        temp = W[i-16] ^ W[i-9] ^ SM3_rot_left32(W[i-3], 15u);
        W[i] = SM3_p1(temp) ^ (SM3_rot_left32(W[i-13], 7u)) ^ W[i-6];
    }

}

void WToW1(const unsigned int W[], unsigned int W1[]){
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
            T = SM3_rot_left32(SM3_T2, 16u);
        } else {
            T = SM3_rot_left32(T, 1u);
        }
        SS1 = SM3_rot_left32((SM3_rot_left32(A, 12u) + E + T), 7u);
        SS2 = SS1 ^ SM3_rot_left32(A, 12u);
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
        C = SM3_rot_left32(B, 9u);
        B = A;
        A = TT1;
        H = G;
        G = SM3_rot_left32(F, 19u);
        F = E;
        E = SM3_p0(TT2);
    }

    V[0] = A ^ V[0];
    V[1] = B ^ V[1];
    V[2] = C ^ V[2];
    V[3] = D ^ V[3];
    V[4] = E ^ V[4];
    V[5] = F ^ V[5];
    V[6] = G ^ V[6];
    V[7] = H ^ V[7];
}

void SM3_compress(SM3_STATE * md){
    unsigned int W[68];
    unsigned int W1[64];
    BiToW(md->buf, W);
    WToW1(W, W1);
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

void SM3_done(SM3_STATE *md, char hash[]){
    int i;
    md->length += md->curlen << 3u;
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
    md->buf[63] = md->length & 0xffu;
    md->buf[62] = (md->length >> 8u) & 0xffu;
    md->buf[61] = (md->length >> 16u) & 0xffu;
    md->buf[60] = (md->length >> 24u) & 0xffu;
    SM3_compress(md);
    int temp = 0;
    for(i = 0; i < 8; ++i) {
        temp += sprintf_s(hash + temp, 9, "%08x", md->state[i]);
    }
}

void SM3_256(unsigned char buf[], int len, char hash[]){
    SM3_STATE md;
    SM3_init(&md);
    SM3_process(&md, buf, len);
    SM3_done(&md, hash);
}
