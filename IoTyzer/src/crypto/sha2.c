#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <crypto/sha2.h>


#define SHA256_DIGEST_BLOCKLEN		64
#define SHA384_DIGEST_BLOCKLEN		128
#define SHA512_DIGEST_BLOCKLEN		128
#define SHA224_DIGEST_VALUELEN		28
#define SHA256_DIGEST_VALUELEN		32
#define SHA384_DIGEST_VALUELEN		48
#define SHA512_DIGEST_VALUELEN		64

#define MAC_ROTL_UNWORD(x, n) ((x << n)^(x >> (32-n)))
#define MAC_ROTR_UNWORD(x, n) ((x >> n)^(x << (32-n)))
#define MAC_ENDIAN_REVERSE_UNWORD(dwS) ((MAC_ROTL_UNWORD((dwS),  8) & 0x00ff00ff) |	(MAC_ROTL_UNWORD((dwS), 24) & 0xff00ff00))
#define MAC_BIG_B2D(B, D) ((D) = MAC_ENDIAN_REVERSE_UNWORD(*(unsigned int*)(B)))
#define MAC_BIG_D2B(D, B) (*(unsigned int*)(B) = MAC_ENDIAN_REVERSE_UNWORD(D))
#define MAC_W2B(B, W, ind) (B[ind] = (W[ind / 4] >> (24 - 8 * (ind % 4))) & 0xff)

#define MAC_GetData(x) MAC_ENDIAN_REVERSE_UNWORD(x)

#define MAC_Ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define MAC_Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define MAC_SR(x, n) ((x) >> (n))
#define MAC_RR(x, n) (((x) >> (n)) ^ ((x) << (32-(n))))
#define MAC_RL(x, n) (((x) << (n)) ^ ((x) >> (32-(n))))
#define MAC_SUM0(x) (MAC_RR((x),  2) ^ MAC_RR((x), 13) ^ MAC_RR((x), 22))
#define MAC_SUM1(x) (MAC_RR((x),  6) ^ MAC_RR((x), 11) ^ MAC_RR((x), 25))
#define MAC_SIGMA0(x) (MAC_RR((x),  7) ^ MAC_RR((x), 18) ^ MAC_SR((x),  3))
#define MAC_SIGMA1(x) (MAC_RR((x), 17) ^ MAC_RR((x), 19) ^ MAC_SR((x), 10))
#define MAC_FF(a, b, c, d, e, f, g, h, i) {							\
	(T1) = (h) + MAC_SUM1(e) + MAC_Ch(e, f, g) + SHA_K[i] + W[i];	\
	(d) += (T1);													\
	(h) = (T1) + MAC_SUM0(a) + MAC_Maj(a, b, c);					\
}
#define MAC_RL_SHA512(x, n) (((x) << n) ^ ((x) >> (32-n)))
#define MAC_ROTL_64_SHA512(x, n) {					\
	tmp = (x)[0];									\
	(x)[0] = ((x)[0] << n) | ((x)[1] >> (32-n));	\
	(x)[1] = ((x)[1] << n) | (tmp    >> (32-n));	\
}
#define MAC_RR_SHA512(x, n) (((x) >> n) ^ ((x) << (32-n)))
#define MAC_ROTR_64_SHA512(x, n) {					\
	tmp = (x)[0];									\
	(x)[0] = ((x)[0] >> n) | ((x)[1] << (32-n));	\
	(x)[1] = ((x)[1] >> n) | (tmp    << (32-n));	\
}
#define MAC_ENDIAN_REVERSE_UNWORD_SHA512(dws) ((MAC_RL_SHA512((dws),  8) & 0x00ff00ff) | (MAC_RL_SHA512((dws), 24) & 0xff00ff00))
#define MAC_ENDIAN_REVERSE_64_SHA512(dwS) {					\
	tmp = MAC_ENDIAN_REVERSE_UNWORD_SHA512((dws)[0]);		\
	(dws)[0] = MAC_ENDIAN_REVERSE_UNWORD_SHA512((dws)[1]);	\
	(dws)[1] = tmp;											\
}
#define MAC_W2B_SHA512(B, W, ind) {							\
	B[ind] = (W[ind / 4] >> (24 - 8 * (ind % 4))) & 0xff;	\
}
#define MAC_GetData_SHA512(x) MAC_ENDIAN_REVERSE_UNWORD_SHA512(x)
#define MAC_Ch_SHA512(x, y, z) ((x & y) ^ ((~x) & z))
#define MAC_Ch_64_SHA512(x, y, z, r) {				\
	(r)[0] = MAC_Ch_SHA512((x)[0], (y)[0], (z)[0]);	\
	(r)[1] = MAC_Ch_SHA512((x)[1], (y)[1], (z)[1]);	\
}
#define MAC_Maj_SHA512(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define MAC_Maj_64_SHA512(x, y, z, r) {					\
	(r)[0] = MAC_Maj_SHA512((x)[0], (y)[0], (z)[0]);	\
	(r)[1] = MAC_Maj_SHA512((x)[1], (y)[1], (z)[1]);	\
}
#define MAC_SR_SHA512(x, n) (x >> n)
#define MAC_SR_64_SHA512(x, n, r) {			\
	(r)[1] = MAC_SR_SHA512((x)[1], n);		\
	(r)[1] = (r)[1] | ((x)[0] << (32-n));	\
	(r)[0] = MAC_SR_SHA512((x)[0], n);		\
}
#define MAC_SUM0_64_SHA512(x, r) {																\
	unsigned int _a[2] = {(x)[0], (x)[1]}, _b[2] = {(x)[1], (x)[0]}, _c[2] = {(x)[1], (x)[0]};	\
	MAC_ROTR_64_SHA512(_a, 28);																	\
	MAC_ROTR_64_SHA512(_b,  2);																	\
	MAC_ROTR_64_SHA512(_c,  7);																	\
	(r)[0] = _a[0] ^ _b[0] ^ _c[0];																\
	(r)[1] = _a[1] ^ _b[1] ^ _c[1];																\
}
#define MAC_SUM1_64_SHA512(x, r) {																\
	unsigned int _a[2] = {(x)[0], (x)[1]}, _b[2] = {(x)[0], (x)[1]}, _c[2] = {(x)[1], (x)[0]};	\
	MAC_ROTR_64_SHA512(_a, 14);																	\
	MAC_ROTR_64_SHA512(_b, 18);																	\
	MAC_ROTR_64_SHA512(_c,  9);																	\
	(r)[0] = _a[0] ^ _b[0] ^ _c[0];																\
	(r)[1] = _a[1] ^ _b[1] ^ _c[1];																\
}
#define MAC_SIGMA0_64_SHA512(x, r) {															\
	unsigned int _a[2] = {(x)[0], (x)[1]}, _b[2] = {(x)[0], (x)[1]}, _c[2] = {(x)[0], (x)[1]};	\
	MAC_ROTR_64_SHA512(_a, 1);																	\
	MAC_ROTR_64_SHA512(_b, 8);																	\
	MAC_SR_64_SHA512(_c, 7, (r));																\
	(r)[0] = _a[0] ^ _b[0] ^ (r)[0];															\
	(r)[1] = _a[1] ^ _b[1] ^ (r)[1];															\
}
#define MAC_SIGMA1_64_SHA512(x, r) {															\
	unsigned int _a[2] = {(x)[0], (x)[1]}, _b[2] = {(x)[1], (x)[0]}, _c[2] = {(x)[0], (x)[1]};	\
	MAC_ROTR_64_SHA512(_a, 19);																	\
	MAC_ROTR_64_SHA512(_b, 29);																	\
	MAC_SR_64_SHA512(_c, 6, (r));																\
	(r)[0] = _a[0] ^ _b[0] ^ (r)[0];															\
	(r)[1] = _a[1] ^ _b[1] ^ (r)[1];															\
}
#define MAC_FF_64_SHA512(a, b, c, d, e, f, g, h, i) {		\
	Carry = 0;												\
	T1[1] = (h)[1] + W[(i)][1];								\
	if(T1[1] < (h)[1])	Carry++;							\
	T1[1] += SHA512_K[((i)*2)+1];							\
	if(T1[1] < SHA512_K[((i)*2)+1])	Carry++;				\
	MAC_SUM1_64_SHA512((e), (r));							\
	T1[1] += (r)[1];										\
	if(T1[1] < (r)[1])	Carry++;							\
	T1[0] = (h)[0] + W[i][0] + SHA512_K[(i)*2] + (r)[0];	\
	MAC_Ch_64_SHA512((e), (f), (g), (r));					\
	T1[1] += (r)[1];										\
	if(T1[1] < (r)[1])	Carry++;							\
	T1[0] += (r)[0];										\
	T1[0] += Carry;											\
	Carry = 0;												\
	(d)[1] += T1[1];										\
	if((d)[1] < T1[1])	Carry++;							\
	(d)[0] += T1[0];										\
	(d)[0] += Carry++;										\
	Carry = 0;												\
	MAC_SUM0_64_SHA512((a), (r));							\
	(h)[1] = T1[1] + (r)[1];								\
	if((h)[1] < (r)[1])	Carry++;							\
	(h)[0] = T1[0] + (r)[0];								\
	MAC_Maj_64_SHA512((a), (b), (c), (r));					\
	(h)[1] += (r)[1];										\
	if((h)[1] < (r)[1])	Carry++;							\
	(h)[0] += (r)[0];										\
	(h)[0] += Carry;										\
}


static const unsigned int SHA_K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const unsigned int SHA512_K[160] = {
	0x428a2f98,0xd728ae22, 0x71374491,0x23ef65cd, 0xb5c0fbcf,0xec4d3b2f, 0xe9b5dba5,0x8189dbbc, 0x3956c25b,0xf348b538,
	0x59f111f1,0xb605d019, 0x923f82a4,0xaf194f9b, 0xab1c5ed5,0xda6d8118, 0xd807aa98,0xa3030242, 0x12835b01,0x45706fbe,
	0x243185be,0x4ee4b28c, 0x550c7dc3,0xd5ffb4e2, 0x72be5d74,0xf27b896f, 0x80deb1fe,0x3b1696b1, 0x9bdc06a7,0x25c71235,
	0xc19bf174,0xcf692694, 0xe49b69c1,0x9ef14ad2, 0xefbe4786,0x384f25e3, 0x0fc19dc6,0x8b8cd5b5, 0x240ca1cc,0x77ac9c65,
	0x2de92c6f,0x592b0275, 0x4a7484aa,0x6ea6e483, 0x5cb0a9dc,0xbd41fbd4, 0x76f988da,0x831153b5, 0x983e5152,0xee66dfab,
	0xa831c66d,0x2db43210, 0xb00327c8,0x98fb213f, 0xbf597fc7,0xbeef0ee4, 0xc6e00bf3,0x3da88fc2, 0xd5a79147,0x930aa725,
	0x06ca6351,0xe003826f, 0x14292967,0x0a0e6e70, 0x27b70a85,0x46d22ffc, 0x2e1b2138,0x5c26c926, 0x4d2c6dfc,0x5ac42aed,
	0x53380d13,0x9d95b3df, 0x650a7354,0x8baf63de, 0x766a0abb,0x3c77b2a8, 0x81c2c92e,0x47edaee6, 0x92722c85,0x1482353b,
	0xa2bfe8a1,0x4cf10364, 0xa81a664b,0xbc423001, 0xc24b8b70,0xd0f89791, 0xc76c51a3,0x0654be30, 0xd192e819,0xd6ef5218,
	0xd6990624,0x5565a910, 0xf40e3585,0x5771202a, 0x106aa070,0x32bbd1b8, 0x19a4c116,0xb8d2d0c8, 0x1e376c08,0x5141ab53,
	0x2748774c,0xdf8eeb99, 0x34b0bcb5,0xe19b48a8, 0x391c0cb3,0xc5c95a63, 0x4ed8aa4a,0xe3418acb, 0x5b9cca4f,0x7763e373,
	0x682e6ff3,0xd6b2b8a3, 0x748f82ee,0x5defb2fc, 0x78a5636f,0x43172f60, 0x84c87814,0xa1f0ab72, 0x8cc70208,0x1a6439ec,
	0x90befffa,0x23631e28, 0xa4506ceb,0xde82bde9, 0xbef9a3f7,0xb2c67915, 0xc67178f2,0xe372532b, 0xca273ece,0xea26619c,
	0xd186b8c7,0x21c0c207, 0xeada7dd6,0xcde0eb1e, 0xf57d4f7f,0xee6ed178, 0x06f067aa,0x72176fba, 0x0a637dc5,0xa2c898a6,
	0x113f9804,0xbef90dae, 0x1b710b35,0x131c471b, 0x28db77f5,0x23047d84, 0x32caab7b,0x40c72493, 0x3c9ebe0a,0x15c9bebc,
	0x431d67c4,0x9c100d4c, 0x4cc5d4be,0xcb3e42b6, 0x597f299c,0xfc657e2a, 0x5fcb6fab,0x3ad6faec, 0x6c44198c,0x4a475817
};

static unsigned int SHA_Transform(unsigned int *Message, unsigned int *H)
{
	unsigned int a, b, c, d, e, f, g, h, T1, W[64];
	unsigned int i;

	for (i = 0; i < 16; i++)
		W[i] = MAC_GetData(Message[i]);

	for (i = 16; i < 64; i++)
		W[i] = MAC_SIGMA1(W[i - 2]) + W[i - 7] + MAC_SIGMA0(W[i - 15]) + W[i - 16];

	a = H[0];
	b = H[1];
	c = H[2];
	d = H[3];
	e = H[4];
	f = H[5];
	g = H[6];
	h = H[7];

	for (i = 0; i < 64; i += 8)
	{
		MAC_FF(a, b, c, d, e, f, g, h, i + 0);
		MAC_FF(h, a, b, c, d, e, f, g, i + 1);
		MAC_FF(g, h, a, b, c, d, e, f, i + 2);
		MAC_FF(f, g, h, a, b, c, d, e, i + 3);
		MAC_FF(e, f, g, h, a, b, c, d, i + 4);
		MAC_FF(d, e, f, g, h, a, b, c, i + 5);
		MAC_FF(c, d, e, f, g, h, a, b, i + 6);
		MAC_FF(b, c, d, e, f, g, h, a, i + 7);
	}

	H[0] += a;
	H[1] += b;
	H[2] += c;
	H[3] += d;
	H[4] += e;
	H[5] += f;
	H[6] += g;
	H[7] += h;

	return 0;
}

static unsigned int SHA512_Transform(unsigned int *Message, unsigned int(*H)[2])
{
	unsigned int a[2], b[2], c[2], d[2], e[2], f[2], g[2], h[2], r[2];
	unsigned int T1[2], Carry, W[80][2], tmp;
	unsigned int i;

	for (i = 0; i < 16; i++)
	{
		W[i][0] = MAC_GetData_SHA512(Message[i * 2]);
		W[i][1] = MAC_GetData_SHA512(Message[i * 2 + 1]);
	}

	for (i = 16; i < 80; i++)
	{
		Carry = 0;

		W[i][1] = W[i - 7][1] + W[i - 16][1];
		if (W[i][1] < W[i - 7][1])	Carry++;

		MAC_SIGMA1_64_SHA512(W[i - 2], r);

		W[i][1] += r[1];
		if (W[i][1] < r[1])	Carry++;

		W[i][0] = r[0] + W[i - 7][0] + W[i - 16][0];

		MAC_SIGMA0_64_SHA512(W[i - 15], r);

		W[i][1] += r[1];
		if (W[i][1] < r[1])	Carry++;

		W[i][0] += Carry;
		W[i][0] += r[0];
	}

	a[0] = H[0][0];		a[1] = H[0][1];
	b[0] = H[1][0];		b[1] = H[1][1];
	c[0] = H[2][0];		c[1] = H[2][1];
	d[0] = H[3][0];		d[1] = H[3][1];
	e[0] = H[4][0];		e[1] = H[4][1];
	f[0] = H[5][0];		f[1] = H[5][1];
	g[0] = H[6][0];		g[1] = H[6][1];
	h[0] = H[7][0];		h[1] = H[7][1];

	for (i = 0; i < 80; i += 8)
	{
		MAC_FF_64_SHA512(a, b, c, d, e, f, g, h, (i + 0));
		MAC_FF_64_SHA512(h, a, b, c, d, e, f, g, (i + 1));
		MAC_FF_64_SHA512(g, h, a, b, c, d, e, f, (i + 2));
		MAC_FF_64_SHA512(f, g, h, a, b, c, d, e, (i + 3));
		MAC_FF_64_SHA512(e, f, g, h, a, b, c, d, (i + 4));
		MAC_FF_64_SHA512(d, e, f, g, h, a, b, c, (i + 5));
		MAC_FF_64_SHA512(c, d, e, f, g, h, a, b, (i + 6));
		MAC_FF_64_SHA512(b, c, d, e, f, g, h, a, (i + 7));
	}

	H[0][1] += a[1];
	H[0][0] += a[0];
	if (H[0][1] < a[1])	H[0][0]++;

	H[1][1] += b[1];
	H[1][0] += b[0];
	if (H[1][1] < b[1])	H[1][0]++;

	H[2][1] += c[1];
	H[2][0] += c[0];
	if (H[2][1] < c[1])	H[2][0]++;

	H[3][1] += d[1];
	H[3][0] += d[0];
	if (H[3][1] < d[1])	H[3][0]++;

	H[4][1] += e[1];
	H[4][0] += e[0];
	if (H[4][1] < e[1])	H[4][0]++;

	H[5][1] += f[1];
	H[5][0] += f[0];
	if (H[5][1] < f[1])	H[5][0]++;

	H[6][1] += g[1];
	H[6][0] += g[0];
	if (H[6][1] < g[1])	H[6][0]++;

	H[7][1] += h[1];
	H[7][0] += h[0];
	if (H[7][1] < h[1])	H[7][0]++;

	return 0;
}

static unsigned int SHA256(unsigned char *Digest, unsigned char *Message, unsigned int MessageLen, int sha_size)
{
	unsigned char Buffer[64];
	unsigned int H224[8] = { 0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4 };
	unsigned int H256[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	unsigned int H[8] = { 0, };
	unsigned int Count[2] = { 0, };
	unsigned int Index, CountH, CountL;
	int i;

	Count[0] += MessageLen << 3;
	Count[1] += MessageLen >> 29;

	if (sha_size == SHA224_DIGEST_VALUELEN)
	{
		for (i = 0; i < 8; i++)
			H[i] = H224[i];
	}
	else
	{
		for (i = 0; i < 8; i++)
			H[i] = H256[i];
	}

	while (MessageLen >= SHA256_DIGEST_BLOCKLEN)
	{
		memcpy(Buffer, Message, SHA256_DIGEST_BLOCKLEN);
		SHA_Transform((unsigned int *)Buffer, H);
		Message += SHA256_DIGEST_BLOCKLEN;
		MessageLen -= SHA256_DIGEST_BLOCKLEN;
	}

	memcpy(Buffer, Message, (int)MessageLen);

	CountL = Count[0];
	CountH = Count[1];

	Index = (Count[0] >> 3) % SHA256_DIGEST_BLOCKLEN;
	Buffer[Index++] = 0x80;

	if (Index > SHA256_DIGEST_BLOCKLEN - 8)
	{
		memset(Buffer + Index, 0, SHA256_DIGEST_BLOCKLEN - Index);
		SHA_Transform((unsigned int *)Buffer, H);
		memset(Buffer, 0, SHA256_DIGEST_BLOCKLEN - 8);
	}
	else
		memset(Buffer + Index, 0, SHA256_DIGEST_BLOCKLEN - Index - 8);

	CountL = MAC_ENDIAN_REVERSE_UNWORD(CountL);
	CountH = MAC_ENDIAN_REVERSE_UNWORD(CountH);

	((unsigned int *)Buffer)[SHA256_DIGEST_BLOCKLEN / 4 - 2] = CountH;
	((unsigned int *)Buffer)[SHA256_DIGEST_BLOCKLEN / 4 - 1] = CountL;

	SHA_Transform((unsigned int *)Buffer, H);

	for (i = 0; i < sha_size; i++)
	{
		MAC_W2B(Digest, H, i);
	}

	return 0;
}

static unsigned int SHA384(unsigned char *Digest, unsigned char *Message, unsigned int MessageLen)
{
	unsigned char Buffer[128];

	unsigned int H[8][2] = {
		{0xcbbb9d5d, 0xc1059ed8},{0x629a292a, 0x367cd507},{0x9159015a, 0x3070dd17},{0x152fecd8, 0xf70e5939},
		{0x67332667, 0xffc00b31},{0x8eb44a87, 0x68581511},{0xdb0c2e0d, 0x64f98fa7},{0x47b5481d, 0xbefa4fa4} };

	unsigned int i, Count[2] = { 0, }, Index, CountH, CountL, Result;

	Count[0] += MessageLen << 3;
	Count[1] += MessageLen >> 29;

	while (MessageLen >= SHA384_DIGEST_BLOCKLEN)
	{
		memcpy(Buffer, Message, SHA384_DIGEST_BLOCKLEN);
		SHA512_Transform((unsigned int *)Buffer, H);
		Message += SHA384_DIGEST_BLOCKLEN;
		MessageLen -= SHA384_DIGEST_BLOCKLEN;
	}

	memcpy(Buffer, Message, (int)MessageLen);

	CountL = Count[0];
	CountH = Count[1];

	Index = (Count[0] >> 3) % SHA384_DIGEST_BLOCKLEN;
	Buffer[Index++] = 0x80;

	if (Index > SHA384_DIGEST_BLOCKLEN - 16)
	{
		memset(Buffer + Index, 0, SHA384_DIGEST_BLOCKLEN - Index);
		SHA512_Transform((unsigned int *)Buffer, H);
		memset(Buffer, 0, SHA384_DIGEST_BLOCKLEN - 8);
	}
	else
		memset(Buffer + Index, 0, SHA384_DIGEST_BLOCKLEN - Index - 8);

	CountL = MAC_ENDIAN_REVERSE_UNWORD_SHA512(CountL);
	CountH = MAC_ENDIAN_REVERSE_UNWORD_SHA512(CountH);

	((unsigned int *)Buffer)[SHA384_DIGEST_BLOCKLEN / 4 - 2] = CountH;
	((unsigned int *)Buffer)[SHA384_DIGEST_BLOCKLEN / 4 - 1] = CountL;

	SHA512_Transform((unsigned int *)Buffer, H);

	for (i = 0; i < 8; i++)
	{
		Result = MAC_ENDIAN_REVERSE_UNWORD_SHA512(H[i][0]);
		memcpy(Digest, &Result, 4);
		Digest += 4;

		Result = MAC_ENDIAN_REVERSE_UNWORD_SHA512(H[i][1]);
		memcpy(Digest, &Result, 4);
		Digest += 4;
	}

	return 0;
}

static unsigned char SHA512(unsigned char *Digest, unsigned char *Message, unsigned int MessageLen)
{
	unsigned char Buffer[128];
	unsigned int H[8][2] = {
		{0x6a09e667, 0xf3bcc908},{0xbb67ae85, 0x84caa73b},{0x3c6ef372, 0xfe94f82b},{0xa54ff53a, 0x5f1d36f1},
		{0x510e527f, 0xade682d1},{0x9b05688c, 0x2b3e6c1f},{0x1f83d9ab, 0xfb41bd6b},{0x5be0cd19, 0x137e2179}
	};

	unsigned int i, Count[2] = { 0, }, Index, CountH, CountL, Result;

	Count[0] += MessageLen << 3;
	Count[1] += MessageLen >> 29;

	while (MessageLen >= SHA512_DIGEST_BLOCKLEN)
	{
		memcpy(Buffer, Message, (int)SHA512_DIGEST_BLOCKLEN);
		SHA512_Transform((unsigned int *)Buffer, H);
		Message += SHA512_DIGEST_BLOCKLEN;
		MessageLen -= SHA512_DIGEST_BLOCKLEN;
	}

	memcpy(Buffer, Message, (int)MessageLen);

	CountL = Count[0];
	CountH = Count[1];

	Index = (Count[0] >> 3) % SHA512_DIGEST_BLOCKLEN;
	Buffer[Index++] = 0x80;

	if (Index > SHA512_DIGEST_BLOCKLEN - 16)
	{
		memset(Buffer + Index, 0, SHA512_DIGEST_BLOCKLEN - Index);
		SHA512_Transform((unsigned int *)Buffer, H);
		memset(Buffer, 0, SHA512_DIGEST_BLOCKLEN - 8);
	}
	else
		memset(Buffer + Index, 0, SHA512_DIGEST_BLOCKLEN - Index - 8);

	CountL = MAC_ENDIAN_REVERSE_UNWORD_SHA512(CountL);
	CountH = MAC_ENDIAN_REVERSE_UNWORD_SHA512(CountH);

	((unsigned int *)Buffer)[SHA512_DIGEST_BLOCKLEN / 4 - 2] = CountH;
	((unsigned int *)Buffer)[SHA512_DIGEST_BLOCKLEN / 4 - 1] = CountL;

	SHA512_Transform((unsigned int *)Buffer, H);

	for (i = 0; i < 8; i++)
	{
		Result = MAC_ENDIAN_REVERSE_UNWORD_SHA512(H[i][0]);
		memcpy(Digest, &Result, 4);
		Digest += 4;

		Result = MAC_ENDIAN_REVERSE_UNWORD_SHA512(H[i][1]);
		memcpy(Digest, &Result, 4);
		Digest += 4;
	}

	return 0;
}

unsigned int SHA2(unsigned char *Digest, unsigned char *Message, unsigned int MessageLen, int sha_size)
{
	if (sha_size == SHA224_DIGEST_VALUELEN || sha_size == SHA256_DIGEST_VALUELEN)
	{
		SHA256(Digest, Message, MessageLen, sha_size);
	}
	else if (sha_size == SHA384_DIGEST_VALUELEN)
	{
		SHA384(Digest, Message, MessageLen);
	}
	else if (sha_size == SHA512_DIGEST_VALUELEN)
	{
		SHA512(Digest, Message, MessageLen);
	}
	else
		return 0xffffffff;

	return 0;
}
