/*************************************************************************
	> File Name: SM4.c
	> Author: reforever
	> Mail: 1589626444@qq.com
	> Created Time:2020/5/8.14:27
 ************************************************************************/

#include "SM4.h"
#include <stdio.h>


void SM4_KeySchedule(const unsigned char MK[], unsigned int rk[]){
    int i;
    unsigned int tmp, buf, K[36];
    for(i = 0; i < 4; ++i){
        K[i] = SM4_FK[i] ^ ((unsigned int)(MK[4*i] << 24u) | (unsigned int)(MK[4*i+1] << 16u)
                | (unsigned int)(MK[4*i+2] << 8u) | (unsigned int)(MK[4*i+3]) );
    }
    for(i = 0; i < 32; ++i){
        tmp = K[i+1] ^ K[i+2] ^ K[i+3] ^ SM4_CK[i];
        buf = (SM4_Sbox[(tmp >> 24u) & 0xffu]) << 24u
            | (SM4_Sbox[(tmp >> 16u) & 0xffu]) << 16u
            | (SM4_Sbox[(tmp >> 8u) & 0xffu]) << 8u
            | (SM4_Sbox[tmp & 0xffu]);
        K[i+4] = K[i] ^ ((buf) ^ (SM4_Rot_left32((buf), 13u)) ^ (SM4_Rot_left32((buf), 23u)));
        rk[i] = K[i+4];
    }
}

void SM4_Encrypt(unsigned char MK[], const unsigned char PlainText[], unsigned char CipherText[]){
    unsigned int rk[32], X[36], tmp, buf;
    int i, j;
    SM4_KeySchedule(MK, rk);
    for(j = 0; j < 4; j++){
        X[j] = (unsigned int)(PlainText[j*4] << 24u) | (unsigned int)(PlainText[j*4+1] << 16u)
             | (unsigned int)(PlainText[j*4+2] << 8u) | (unsigned int)(PlainText[j*4+3]);
    }
    for(i = 0; i < 32; i++) {
        tmp = X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i];
        buf = (SM4_Sbox[(tmp >> 24u) & 0xFFu]) << 24u
            | (SM4_Sbox[(tmp >> 16u) & 0xFFu]) << 16u
            | (SM4_Sbox[(tmp >> 8u) & 0xFFu]) << 8u
            | (SM4_Sbox[tmp & 0xFFu]);
        X[i+4] = X[i] ^ (buf ^ SM4_Rot_left32((buf), 2u) ^ SM4_Rot_left32((buf), 10u)
                     ^ SM4_Rot_left32((buf), 18u)^ SM4_Rot_left32((buf), 24u));
    }
    for(j = 0; j < 4; j++){
        CipherText[4*j] = (X[35-j] >> 24u) & 0xFFu;
        CipherText[4*j+1] = (X[35-j] >> 16u) & 0xFFu;
        CipherText[4*j+2] = (X[35-j] >> 8u) & 0xFFu;
        CipherText[4*j+3] = (X[35-j]) & 0xFFu;
    }
}

void SM4_Decrypt(unsigned char MK[], const unsigned char CipherText[], unsigned char PlainText[]){
    unsigned int rk[32], X[36], tmp, buf;
    int i, j;
    SM4_KeySchedule(MK, rk);
    for(j = 0; j < 4; ++j){
        X[j] = (unsigned int)(CipherText[j*4] << 24u) | (unsigned int)(CipherText[j*4+1] << 16u)
             | (unsigned int)(CipherText[j*4+2] << 8u) | (unsigned int)(CipherText[j*4+3]);
    }
    for(i = 0; i < 32; ++i){
        tmp = X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[31-i];
        buf = (SM4_Sbox[(tmp >> 24u) & 0xFFu]) << 24u
            | (SM4_Sbox[(tmp >> 16u) & 0xFFu]) << 16u
            | (SM4_Sbox[(tmp >> 8u) & 0xFFu]) << 8u
            | (SM4_Sbox[tmp & 0xFFu]);
        X[i+4] = X[i] ^ (buf ^ SM4_Rot_left32((buf), 2u) ^ SM4_Rot_left32((buf), 10u)
               ^ SM4_Rot_left32((buf), 18u) ^ SM4_Rot_left32((buf), 24u));
    }
    for(j = 0; j < 4; ++j){
        PlainText[4*j] = (X[35-j] >> 24u)& 0xFFu;
        PlainText[4*j+1] = (X[35-j] >>16u)& 0xFFu;
        PlainText[4*j+2] = (X[35-j] >> 8u)& 0xFFu;
        PlainText[4*j+3] = (X[35-j]) & 0xFFu;
    }
}