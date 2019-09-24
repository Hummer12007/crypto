#include <stdint.h>
#include <assert.h>
#include <wmmintrin.h>
#include "aes.h"
#include "common.h"

void ECB_encrypt(struct cipher *cipher, void *ctx, uint8_t *padded, size_t len) {
	assert(len % cipher->block_len == 0);
	while (len) {
		cipher->encrypt(ctx, padded);
		padded += cipher->block_len;
		len -= cipher->block_len;
	}
}

void ECB_decrypt(struct cipher *cipher, void *ctx, uint8_t *padded, size_t len) {
	assert(len % cipher->block_len == 0);
	while (len) {
		cipher->decrypt(ctx, padded);
		padded += cipher->block_len;
		len -= cipher->block_len;
	}
}

void CBC_encrypt(struct cipher *cipher, void *ctx, uint8_t *padded, size_t len, uint8_t *iv) {
	assert(len % cipher->block_len == 0);
	__m128i xmm1;
	xmm1 = _mm_loadu_si128((const __m128i *) iv);
	while (len) {
		_mm_storeu_si128((__m128i *) padded,
				_mm_xor_si128(xmm1, _mm_loadu_si128((__m128i *)padded)));
		cipher->encrypt(ctx, padded);
		xmm1 = _mm_loadu_si128((const __m128i *) padded);
		padded += cipher->block_len;
		len -= cipher->block_len;
	}
}

void CBC_decrypt(struct cipher *cipher, void *ctx, uint8_t *padded, size_t len, uint8_t *iv) {
	assert(len % cipher->block_len == 0);
	__m128i iv128, niv128;
	iv128 = _mm_loadu_si128((__m128i *) iv);
	while (len) {
		niv128 = _mm_loadu_si128((__m128i *) padded);
		cipher->decrypt(ctx, padded);
		_mm_store_si128((__m128i *) padded,
			_mm_xor_si128(_mm_loadu_si128((__m128i *) padded), iv128));
		iv128 = niv128;
		padded += cipher->block_len;
		len -= cipher->block_len;
	}
}

void CTR_xcrypt(struct cipher *cipher, void *ctx, uint8_t *padded, size_t len, uint8_t *_iv) {
	assert(len % cipher->block_len == 0);
	int i;
	uint8_t buf[16], iv[16];
	// preserve original iv
	_mm_storeu_si128((__m128i *) iv, _mm_loadu_si128((__m128i *) _iv));
	while (len) {
		_mm_storeu_si128((__m128i *) buf, _mm_loadu_si128((__m128i *) iv));
		cipher->encrypt(ctx, buf);
		_mm_store_si128((__m128i *) padded,
			_mm_xor_si128(_mm_loadu_si128((__m128i *) padded),
				_mm_loadu_si128((__m128i *) buf)));
		i = 15;
		//TODO: simd
		do
			++iv[i];
		while (!iv[i] && --i >= 0);
		padded += cipher->block_len;
		len -= cipher->block_len;
	}
}

#define AES128_Nr 10

// :(
static const uint8_t RCON[11] = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

static inline __m128i key_expansion_128(__m128i xmm1, __m128i xmm2)
{
	__m128i xmm3;
	xmm2 = _mm_shuffle_epi32(xmm2, 0xff);
	xmm3 = _mm_slli_si128(xmm1, 0x4);
	xmm1 = _mm_xor_si128(xmm1, xmm3);
	xmm3 = _mm_slli_si128(xmm3, 0x4);
	xmm1 = _mm_xor_si128(xmm1, xmm3);
	xmm3 = _mm_slli_si128(xmm3, 0x4);
	xmm1 = _mm_xor_si128(xmm1, xmm3);
	xmm1 = _mm_xor_si128(xmm1, xmm2);
	return xmm1;
}

static void AES128_init(AES128_ctx ret, const uint8_t *key) {
	__m128i xmm1, xmm2;
	__m128i *keys = (__m128i *)ret;

	xmm1 = _mm_loadu_si128((const __m128i *) key);
	_mm_storeu_si128(keys + 0, xmm1);
	xmm2 = _mm_aeskeygenassist_si128(xmm1, 0x01);
	xmm1 = key_expansion_128(xmm1, xmm2);
	_mm_storeu_si128(keys + 1, xmm1);
	xmm2 = _mm_aeskeygenassist_si128(xmm1, 0x02);
	xmm1 = key_expansion_128(xmm1, xmm2);
	_mm_storeu_si128(keys + 2, xmm1);
	xmm2 = _mm_aeskeygenassist_si128(xmm1, 0x04);
	xmm1 = key_expansion_128(xmm1, xmm2);
	_mm_storeu_si128(keys + 3, xmm1);
	xmm2 = _mm_aeskeygenassist_si128(xmm1, 0x08);
	xmm1 = key_expansion_128(xmm1, xmm2);
	_mm_storeu_si128(keys + 4, xmm1);
	xmm2 = _mm_aeskeygenassist_si128(xmm1, 0x10);
	xmm1 = key_expansion_128(xmm1, xmm2);
	_mm_storeu_si128(keys + 5, xmm1);
	xmm2 = _mm_aeskeygenassist_si128(xmm1, 0x20);
	xmm1 = key_expansion_128(xmm1, xmm2);
	_mm_storeu_si128(keys + 6, xmm1);
	xmm2 = _mm_aeskeygenassist_si128(xmm1, 0x40);
	xmm1 = key_expansion_128(xmm1, xmm2);
	_mm_storeu_si128(keys + 7, xmm1);
	xmm2 = _mm_aeskeygenassist_si128(xmm1, 0x80);
	xmm1 = key_expansion_128(xmm1, xmm2);
	_mm_storeu_si128(keys + 8, xmm1);
	xmm2 = _mm_aeskeygenassist_si128(xmm1, 0x1b);
	xmm1 = key_expansion_128(xmm1, xmm2);
	_mm_storeu_si128(keys + 9, xmm1);
	xmm2 = _mm_aeskeygenassist_si128(xmm1, 0x36);
	xmm1 = key_expansion_128(xmm1, xmm2);
	_mm_storeu_si128(keys + 10, xmm1);
}

static void AES128_encrypt(AES128_ctx key, uint8_t *buf) {
	const __m128i *keys = (__m128i *)key;
	__m128i state;

	state = _mm_loadu_si128((const __m128i *) buf);
	state = _mm_xor_si128(state, keys[0]);
	for (int i = 1; i < AES128_Nr; ++i)
		state = _mm_aesenc_si128(state, keys[i]);
	state = _mm_aesenclast_si128(state, keys[AES128_Nr]);
	_mm_storeu_si128((__m128i *) buf, state);

}

static void AES128_decrypt(AES128_ctx key, uint8_t *buf) {
	const __m128i *keys = (__m128i *)key;
	__m128i state;

	state = _mm_loadu_si128((const __m128i *) buf);
	state = _mm_xor_si128(state, keys[AES128_Nr]);
	for (int i = AES128_Nr - 1; i > 0; --i)
		state = _mm_aesdec_si128(state, _mm_aesimc_si128(keys[i]));
	state = _mm_aesdeclast_si128(state, keys[0]);
	_mm_storeu_si128((__m128i *) buf, state);
}

cipher_impl(AES128, 16);

