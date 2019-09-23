#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

struct cipher {
	size_t block_len;
	void (*init)(void *target, const uint8_t *key);
	void (*encrypt)(const void *round_key, uint8_t *buf);
	void (*decrypt)(const void *round_key, uint8_t *buf);
};

#define cipher_impl(CIPHER, len) \
	struct cipher CIPHER = {\
		.block_len = len,\
		.init = (void (*)(void *, const uint8_t *)) & CIPHER ##_init,\
		.encrypt = (void (*)(const void *, uint8_t *)) & CIPHER ##_encrypt,\
		.decrypt = (void (*)(const void *, uint8_t *)) & CIPHER ##_decrypt,\
	}

extern struct cipher AES128;
typedef uint8_t AES128_ctx[176];

extern struct cipher AES128;
typedef uint8_t AES256_ctx[240];

void ECB_encrypt(struct cipher *cipher, void *ctx, uint8_t *padded, size_t len);
void ECB_decrypt(struct cipher *cipher, void *ctx, uint8_t *padded, size_t len);

void CBC_encrypt(struct cipher *cipher, void *ctx, uint8_t *padded, size_t len, uint8_t *iv);
void CBC_decrypt(struct cipher *cipher, void *ctx, uint8_t *padded, size_t len, uint8_t *iv);

void CTR_xcrypt(struct cipher *cipher, void *ctx, uint8_t *padded, size_t len, uint8_t *iv);

enum stream_mode {
	ECB,
	CBC,
	CTR,
};

typedef void (*enc_fun)(struct cipher *, void *, uint8_t *, size_t, uint8_t *);

struct stream_impl {
	enc_fun encrypt;
	enc_fun decrypt;
};

static struct stream_impl streams[] = {
	{(enc_fun)ECB_encrypt, (enc_fun)ECB_decrypt},
	{CBC_encrypt, CBC_decrypt},
	{CTR_xcrypt, CTR_xcrypt},
};


#endif //_AES_H_
