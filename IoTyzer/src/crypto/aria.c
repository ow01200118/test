#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <crypto/aria.h>


#define MAC_AAA(V) 0x ## 00 ## V ## V ## V
#define MAC_BBB(V) 0x ## V ## 00 ## V ## V
#define MAC_CCC(V) 0x ## V ## V ## 00 ## V
#define MAC_DDD(V) 0x ## V ## V ## V ## 00
#define MAC_XX(NNN,x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf)		\
	NNN(x0),NNN(x1),NNN(x2),NNN(x3),NNN(x4),NNN(x5),NNN(x6),NNN(x7),	\
	NNN(x8),NNN(x9),NNN(xa),NNN(xb),NNN(xc),NNN(xd),NNN(xe),NNN(xf)
#define MAC_BY(X,Y) (((IOTZ_UBYTE *)(&X))[Y])
#define MAC_BRF(T,R) ((IOTZ_UBYTE)((T)>>(R)))
#define MAC_WO(X,Y) (((IOTZ_UWORD *)(X))[Y])
#define MAC_ReverseWord(W) {											\
    (W)=(W)<<24 ^ (W)>>24 ^ ((W)&0x0000ff00)<<8 ^ ((W)&0x00ff0000)>>8;	\
}
#define MAC_WordLoad(ORIG, DEST) {	\
    IOTZ_UWORD ___t;				\
    MAC_BY(___t,0)=MAC_BY(ORIG,3);	\
    MAC_BY(___t,1)=MAC_BY(ORIG,2);	\
    MAC_BY(___t,2)=MAC_BY(ORIG,1);	\
    MAC_BY(___t,3)=MAC_BY(ORIG,0);	\
    DEST=___t;						\
}
#define MAC_KXL {								\
    t0^=rk[0]; t1^=rk[1]; t2^=rk[2]; t3^=rk[3];	\
    rk += 4;									\
}
#define MAC_SBL1_M(T0,T1,T2,T3) {													\
    T0=s1[MAC_BRF(T0,24)]^s2[MAC_BRF(T0,16)]^x1[MAC_BRF(T0,8)]^x2[MAC_BRF(T0,0)];	\
    T1=s1[MAC_BRF(T1,24)]^s2[MAC_BRF(T1,16)]^x1[MAC_BRF(T1,8)]^x2[MAC_BRF(T1,0)];	\
    T2=s1[MAC_BRF(T2,24)]^s2[MAC_BRF(T2,16)]^x1[MAC_BRF(T2,8)]^x2[MAC_BRF(T2,0)];	\
    T3=s1[MAC_BRF(T3,24)]^s2[MAC_BRF(T3,16)]^x1[MAC_BRF(T3,8)]^x2[MAC_BRF(T3,0)];	\
}
#define MAC_SBL2_M(T0,T1,T2,T3) {													\
    T0=x1[MAC_BRF(T0,24)]^x2[MAC_BRF(T0,16)]^s1[MAC_BRF(T0,8)]^s2[MAC_BRF(T0,0)];	\
    T1=x1[MAC_BRF(T1,24)]^x2[MAC_BRF(T1,16)]^s1[MAC_BRF(T1,8)]^s2[MAC_BRF(T1,0)];	\
    T2=x1[MAC_BRF(T2,24)]^x2[MAC_BRF(T2,16)]^s1[MAC_BRF(T2,8)]^s2[MAC_BRF(T2,0)];	\
    T3=x1[MAC_BRF(T3,24)]^x2[MAC_BRF(T3,16)]^s1[MAC_BRF(T3,8)]^s2[MAC_BRF(T3,0)];	\
}
#define MAC_SBL3_M(T0,T1,T2,T3) {																										\
    T0=(x1[MAC_BRF(T0,24)]&0xff000000)^(x2[MAC_BRF(T0,16)]&0x00ff0000)^(s1[MAC_BRF(T0,8)]&0x0000ff00)^(s2[MAC_BRF(T0,0)]&0x000000ff);	\
    T1=(x1[MAC_BRF(T1,24)]&0xff000000)^(x2[MAC_BRF(T1,16)]&0x00ff0000)^(s1[MAC_BRF(T1,8)]&0x0000ff00)^(s2[MAC_BRF(T1,0)]&0x000000ff);	\
    T2=(x1[MAC_BRF(T2,24)]&0xff000000)^(x2[MAC_BRF(T2,16)]&0x00ff0000)^(s1[MAC_BRF(T2,8)]&0x0000ff00)^(s2[MAC_BRF(T2,0)]&0x000000ff);	\
    T3=(x1[MAC_BRF(T3,24)]&0xff000000)^(x2[MAC_BRF(T3,16)]&0x00ff0000)^(s1[MAC_BRF(T3,8)]&0x0000ff00)^(s2[MAC_BRF(T3,0)]&0x000000ff);	\
}
#define MAC_MM(T0,T1,T2,T3) {			\
    (T1)^=(T2); (T2)^=(T3); (T0)^=(T1);	\
    (T3)^=(T1); (T2)^=(T0); (T1)^=(T2);	\
}
#define MAC_P(T0,T1,T2,T3) {									\
    (T1) = (((T1)<< 8)&0xff00ff00) ^ (((T1)>> 8)&0x00ff00ff);	\
    (T2) = (((T2)<<16)&0xffff0000) ^ (((T2)>>16)&0x0000ffff);	\
    MAC_ReverseWord((T3));										\
}
#define MAC_WordM1(X,Y) {										\
	Y=(X)<<8 ^ (X)>>8 ^ (X)<<16 ^ (X)>>16 ^ (X)<<24 ^ (X)>>24;	\
}
#define MAC_FO {MAC_SBL1_M(t0,t1,t2,t3) MAC_MM(t0,t1,t2,t3) MAC_P(t0,t1,t2,t3) MAC_MM(t0,t1,t2,t3)}
#define MAC_FE {MAC_SBL2_M(t0,t1,t2,t3) MAC_MM(t0,t1,t2,t3) MAC_P(t2,t3,t0,t1) MAC_MM(t0,t1,t2,t3)}
#define MAC_GSRK(X, Y, n) {												\
    q = 4-((n)/32);														\
    r = (n) % 32;														\
    rk[0] = ((X)[0]) ^ (((Y)[(q  )%4])>>r) ^ (((Y)[(q+3)%4])<<(32-r));	\
    rk[1] = ((X)[1]) ^ (((Y)[(q+1)%4])>>r) ^ (((Y)[(q  )%4])<<(32-r));	\
    rk[2] = ((X)[2]) ^ (((Y)[(q+2)%4])>>r) ^ (((Y)[(q+1)%4])<<(32-r));	\
    rk[3] = ((X)[3]) ^ (((Y)[(q+3)%4])>>r) ^ (((Y)[(q+2)%4])<<(32-r));	\
    rk += 4;															\
}


static const IOTZ_UWORD s1[256] =
{
    MAC_XX(MAC_AAA,63,7c,77,7b,f2,6b,6f,c5,30,01,67,2b,fe,d7,ab,76),
    MAC_XX(MAC_AAA,ca,82,c9,7d,fa,59,47,f0,ad,d4,a2,af,9c,a4,72,c0),
    MAC_XX(MAC_AAA,b7,fd,93,26,36,3f,f7,cc,34,a5,e5,f1,71,d8,31,15),
    MAC_XX(MAC_AAA,04,c7,23,c3,18,96,05,9a,07,12,80,e2,eb,27,b2,75),
    MAC_XX(MAC_AAA,09,83,2c,1a,1b,6e,5a,a0,52,3b,d6,b3,29,e3,2f,84),
    MAC_XX(MAC_AAA,53,d1,00,ed,20,fc,b1,5b,6a,cb,be,39,4a,4c,58,cf),
    MAC_XX(MAC_AAA,d0,ef,aa,fb,43,4d,33,85,45,f9,02,7f,50,3c,9f,a8),
    MAC_XX(MAC_AAA,51,a3,40,8f,92,9d,38,f5,bc,b6,da,21,10,ff,f3,d2),
    MAC_XX(MAC_AAA,cd,0c,13,ec,5f,97,44,17,c4,a7,7e,3d,64,5d,19,73),
    MAC_XX(MAC_AAA,60,81,4f,dc,22,2a,90,88,46,ee,b8,14,de,5e,0b,db),
    MAC_XX(MAC_AAA,e0,32,3a,0a,49,06,24,5c,c2,d3,ac,62,91,95,e4,79),
    MAC_XX(MAC_AAA,e7,c8,37,6d,8d,d5,4e,a9,6c,56,f4,ea,65,7a,ae,08),
    MAC_XX(MAC_AAA,ba,78,25,2e,1c,a6,b4,c6,e8,dd,74,1f,4b,bd,8b,8a),
    MAC_XX(MAC_AAA,70,3e,b5,66,48,03,f6,0e,61,35,57,b9,86,c1,1d,9e),
    MAC_XX(MAC_AAA,e1,f8,98,11,69,d9,8e,94,9b,1e,87,e9,ce,55,28,df),
    MAC_XX(MAC_AAA,8c,a1,89,0d,bf,e6,42,68,41,99,2d,0f,b0,54,bb,16)
};

static const IOTZ_UWORD s2[256] =
{
    MAC_XX(MAC_BBB,e2,4e,54,fc,94,c2,4a,cc,62,0d,6a,46,3c,4d,8b,d1),
    MAC_XX(MAC_BBB,5e,fa,64,cb,b4,97,be,2b,bc,77,2e,03,d3,19,59,c1),
    MAC_XX(MAC_BBB,1d,06,41,6b,55,f0,99,69,ea,9c,18,ae,63,df,e7,bb),
    MAC_XX(MAC_BBB,00,73,66,fb,96,4c,85,e4,3a,09,45,aa,0f,ee,10,eb),
    MAC_XX(MAC_BBB,2d,7f,f4,29,ac,cf,ad,91,8d,78,c8,95,f9,2f,ce,cd),
    MAC_XX(MAC_BBB,08,7a,88,38,5c,83,2a,28,47,db,b8,c7,93,a4,12,53),
    MAC_XX(MAC_BBB,ff,87,0e,31,36,21,58,48,01,8e,37,74,32,ca,e9,b1),
    MAC_XX(MAC_BBB,b7,ab,0c,d7,c4,56,42,26,07,98,60,d9,b6,b9,11,40),
    MAC_XX(MAC_BBB,ec,20,8c,bd,a0,c9,84,04,49,23,f1,4f,50,1f,13,dc),
    MAC_XX(MAC_BBB,d8,c0,9e,57,e3,c3,7b,65,3b,02,8f,3e,e8,25,92,e5),
    MAC_XX(MAC_BBB,15,dd,fd,17,a9,bf,d4,9a,7e,c5,39,67,fe,76,9d,43),
    MAC_XX(MAC_BBB,a7,e1,d0,f5,68,f2,1b,34,70,05,a3,8a,d5,79,86,a8),
    MAC_XX(MAC_BBB,30,c6,51,4b,1e,a6,27,f6,35,d2,6e,24,16,82,5f,da),
    MAC_XX(MAC_BBB,e6,75,a2,ef,2c,b2,1c,9f,5d,6f,80,0a,72,44,9b,6c),
    MAC_XX(MAC_BBB,90,0b,5b,33,7d,5a,52,f3,61,a1,f7,b0,d6,3f,7c,6d),
    MAC_XX(MAC_BBB,ed,14,e0,a5,3d,22,b3,f8,89,de,71,1a,af,ba,b5,81)
};

static const IOTZ_UWORD x1[256] =
{
    MAC_XX(MAC_CCC,52,09,6a,d5,30,36,a5,38,bf,40,a3,9e,81,f3,d7,fb),
    MAC_XX(MAC_CCC,7c,e3,39,82,9b,2f,ff,87,34,8e,43,44,c4,de,e9,cb),
    MAC_XX(MAC_CCC,54,7b,94,32,a6,c2,23,3d,ee,4c,95,0b,42,fa,c3,4e),
    MAC_XX(MAC_CCC,08,2e,a1,66,28,d9,24,b2,76,5b,a2,49,6d,8b,d1,25),
    MAC_XX(MAC_CCC,72,f8,f6,64,86,68,98,16,d4,a4,5c,cc,5d,65,b6,92),
    MAC_XX(MAC_CCC,6c,70,48,50,fd,ed,b9,da,5e,15,46,57,a7,8d,9d,84),
    MAC_XX(MAC_CCC,90,d8,ab,00,8c,bc,d3,0a,f7,e4,58,05,b8,b3,45,06),
    MAC_XX(MAC_CCC,d0,2c,1e,8f,ca,3f,0f,02,c1,af,bd,03,01,13,8a,6b),
    MAC_XX(MAC_CCC,3a,91,11,41,4f,67,dc,ea,97,f2,cf,ce,f0,b4,e6,73),
    MAC_XX(MAC_CCC,96,ac,74,22,e7,ad,35,85,e2,f9,37,e8,1c,75,df,6e),
    MAC_XX(MAC_CCC,47,f1,1a,71,1d,29,c5,89,6f,b7,62,0e,aa,18,be,1b),
    MAC_XX(MAC_CCC,fc,56,3e,4b,c6,d2,79,20,9a,db,c0,fe,78,cd,5a,f4),
    MAC_XX(MAC_CCC,1f,dd,a8,33,88,07,c7,31,b1,12,10,59,27,80,ec,5f),
    MAC_XX(MAC_CCC,60,51,7f,a9,19,b5,4a,0d,2d,e5,7a,9f,93,c9,9c,ef),
    MAC_XX(MAC_CCC,a0,e0,3b,4d,ae,2a,f5,b0,c8,eb,bb,3c,83,53,99,61),
    MAC_XX(MAC_CCC,17,2b,04,7e,ba,77,d6,26,e1,69,14,63,55,21,0c,7d)
};

static const IOTZ_UWORD x2[256] =
{
    MAC_XX(MAC_DDD,30,68,99,1b,87,b9,21,78,50,39,db,e1,72,09,62,3c),
    MAC_XX(MAC_DDD,3e,7e,5e,8e,f1,a0,cc,a3,2a,1d,fb,b6,d6,20,c4,8d),
    MAC_XX(MAC_DDD,81,65,f5,89,cb,9d,77,c6,57,43,56,17,d4,40,1a,4d),
    MAC_XX(MAC_DDD,c0,63,6c,e3,b7,c8,64,6a,53,aa,38,98,0c,f4,9b,ed),
    MAC_XX(MAC_DDD,7f,22,76,af,dd,3a,0b,58,67,88,06,c3,35,0d,01,8b),
    MAC_XX(MAC_DDD,8c,c2,e6,5f,02,24,75,93,66,1e,e5,e2,54,d8,10,ce),
    MAC_XX(MAC_DDD,7a,e8,08,2c,12,97,32,ab,b4,27,0a,23,df,ef,ca,d9),
    MAC_XX(MAC_DDD,b8,fa,dc,31,6b,d1,ad,19,49,bd,51,96,ee,e4,a8,41),
    MAC_XX(MAC_DDD,da,ff,cd,55,86,36,be,61,52,f8,bb,0e,82,48,69,9a),
    MAC_XX(MAC_DDD,e0,47,9e,5c,04,4b,34,15,79,26,a7,de,29,ae,92,d7),
    MAC_XX(MAC_DDD,84,e9,d2,ba,5d,f3,c5,b0,bf,a4,3b,71,44,46,2b,fc),
    MAC_XX(MAC_DDD,eb,6f,d5,f6,14,fe,7c,70,5a,7d,fd,2f,18,83,16,a5),
    MAC_XX(MAC_DDD,91,1f,05,95,74,a9,c1,5b,4a,85,6d,13,07,4f,4e,45),
    MAC_XX(MAC_DDD,b2,0f,c9,1c,a6,bc,ec,73,90,7b,cf,59,8f,a1,f9,2d),
    MAC_XX(MAC_DDD,f2,b1,00,94,37,9f,d0,2e,9c,6e,28,3f,80,f0,3d,d3),
    MAC_XX(MAC_DDD,25,8a,b5,e7,42,b3,c7,ea,f7,4c,11,33,03,a2,ac,60)
};

static const IOTZ_UWORD krk[3][4] =
{
    {0x517cc1b7, 0x27220a94, 0xfe13abe8, 0xfa9a6ee0},
    {0x6db14acc, 0x9e21c820, 0xff28b1d5, 0xef5de2b0},
    {0xdb92371d, 0x2126e970, 0x03249775, 0x04e8c90e}
};


IOTZ_RETURN expand_enckey_aria(IOTZ_UWORD* rk, const IOTZ_UWORD* key, const IOTZ_INT keyLen)
{
    register IOTZ_UWORD t0, t1, t2, t3;
    IOTZ_UWORD w0[4], w1[4], w2[4], w3[4];
    IOTZ_UWORD q, r;

    w0[0] = key[0];
    w0[1] = key[1];
    w0[2] = key[2];
    w0[3] = key[3];

    if (keyLen == 4)
        q = 0;
    else if (keyLen == 6)
        q = 1;
    else
        q = 2;

    t0 = w0[0] ^ krk[q][0];
    t1 = w0[1] ^ krk[q][1];
    t2 = w0[2] ^ krk[q][2];
    t3 = w0[3] ^ krk[q][3];
    MAC_FO;

    if (q == 0)
    {
        w1[0] = w1[1] = w1[2] = w1[3] = 0;
    }
    else
    {
        w1[0] = key[4];
        w1[1] = key[5];

        if (q > 1)
        {
            w1[2] = key[6];
            w1[3] = key[7];
        }
        else
            w1[2] = w1[3] = 0;
    }

    w1[0] ^= t0; w1[1] ^= t1; w1[2] ^= t2; w1[3] ^= t3;
    t0 = w1[0];  t1 = w1[1];  t2 = w1[2];  t3 = w1[3];

    q = (q == 2) ? 0 : (q + 1);
    t0 ^= krk[q][0]; t1 ^= krk[q][1]; t2 ^= krk[q][2]; t3 ^= krk[q][3];
    MAC_FE;
    t0 ^= w0[0]; t1 ^= w0[1]; t2 ^= w0[2]; t3 ^= w0[3];
    w2[0] = t0; w2[1] = t1; w2[2] = t2; w2[3] = t3;

    q = (q == 2) ? 0 : (q + 1);
    t0 ^= krk[q][0]; t1 ^= krk[q][1]; t2 ^= krk[q][2]; t3 ^= krk[q][3];
    MAC_FO;
    w3[0] = t0 ^ w1[0]; w3[1] = t1 ^ w1[1]; w3[2] = t2 ^ w1[2]; w3[3] = t3 ^ w1[3];

    MAC_GSRK(w0, w1, 19);
    MAC_GSRK(w1, w2, 19);
    MAC_GSRK(w2, w3, 19);
    MAC_GSRK(w3, w0, 19);
    MAC_GSRK(w0, w1, 31);
    MAC_GSRK(w1, w2, 31);
    MAC_GSRK(w2, w3, 31);
    MAC_GSRK(w3, w0, 31);
    MAC_GSRK(w0, w1, 67);
    MAC_GSRK(w1, w2, 67);
    MAC_GSRK(w2, w3, 67);
    MAC_GSRK(w3, w0, 67);
    MAC_GSRK(w0, w1, 97);

    if (keyLen > 4)
    {
        MAC_GSRK(w1, w2, 97);
        MAC_GSRK(w2, w3, 97);
    }
    if (keyLen > 6)
    {
        MAC_GSRK(w3, w0, 97);
        MAC_GSRK(w0, w1, 109);
    }

    return IOTZ_OK;
}

IOTZ_RETURN expand_deckey_aria(IOTZ_UWORD* rk, const IOTZ_UWORD* key, const IOTZ_INT keyLen)
{
    IOTZ_UWORD* a, * z;
    IOTZ_UWORD rValue = keyLen + 8;
    register IOTZ_UWORD t0, t1, t2, t3;
    IOTZ_UWORD s0, s1, s2, s3;

    expand_enckey_aria(rk, key, keyLen);
    a = rk; z = a + rValue * 4;
    t0 = a[0]; t1 = a[1]; t2 = a[2]; t3 = a[3];
    a[0] = z[0]; a[1] = z[1]; a[2] = z[2]; a[3] = z[3];
    z[0] = t0; z[1] = t1; z[2] = t2; z[3] = t3;
    a += 4; z -= 4;

    for (; a < z; a += 4, z -= 4)
    {
        MAC_WordM1(a[0], t0); MAC_WordM1(a[1], t1); MAC_WordM1(a[2], t2); MAC_WordM1(a[3], t3);
        MAC_MM(t0, t1, t2, t3) MAC_P(t0, t1, t2, t3) MAC_MM(t0, t1, t2, t3)
            s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        MAC_WordM1(z[0], t0); MAC_WordM1(z[1], t1); MAC_WordM1(z[2], t2); MAC_WordM1(z[3], t3);
        MAC_MM(t0, t1, t2, t3) MAC_P(t0, t1, t2, t3) MAC_MM(t0, t1, t2, t3)
            a[0] = t0; a[1] = t1; a[2] = t2; a[3] = t3;
        z[0] = s0; z[1] = s1; z[2] = s2; z[3] = s3;
    }

    MAC_WordM1(a[0], t0); MAC_WordM1(a[1], t1); MAC_WordM1(a[2], t2); MAC_WordM1(a[3], t3);
    MAC_MM(t0, t1, t2, t3) MAC_P(t0, t1, t2, t3) MAC_MM(t0, t1, t2, t3)
        z[0] = t0; z[1] = t1; z[2] = t2; z[3] = t3;

    return IOTZ_OK;
}

IOTZ_RETURN crypt_aria(IOTZ_UWORD* output, const IOTZ_UWORD* input, const IOTZ_INT keyLen, const IOTZ_BLOCK_ENC_DEC sit, const IOTZ_UWORD* rk)
{
    IOTZ_UWORD t0, t1, t2, t3;

    t0 = input[0];
    t1 = input[1];
    t2 = input[2];
    t3 = input[3];

    if (keyLen > 4) { MAC_KXL MAC_FO MAC_KXL MAC_FE }
    if (keyLen > 6) { MAC_KXL MAC_FO MAC_KXL MAC_FE }
    MAC_KXL MAC_FO
        MAC_KXL MAC_FE
        MAC_KXL MAC_FO
        MAC_KXL MAC_FE
        MAC_KXL MAC_FO
        MAC_KXL MAC_FE
        MAC_KXL MAC_FO
        MAC_KXL MAC_FE
        MAC_KXL MAC_FO
        MAC_KXL MAC_FE
        MAC_KXL MAC_FO
        MAC_KXL
        MAC_SBL3_M(t0, t1, t2, t3)
        MAC_KXL

    output[0] = t0;
    output[1] = t1;
    output[2] = t2;
    output[3] = t3;

    return IOTZ_OK;
}


