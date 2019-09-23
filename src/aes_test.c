#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "aes.h"
#include "hexify.h"

static unsigned char *test_text = "00112233445566778899aabbccddeeff";
static unsigned char *test_out = "69c4e0d86a7b0430d8cdb78070b4c55a";

static unsigned char *test_key = "000102030405060708090a0b0c0d0e0f";
static unsigned char *test_last_key = "13111d7fe3944a17f307a78b4d2b30c5";


static unsigned char text_buf[16];
static unsigned char orig_buf[16];
static unsigned char key_buf[16];
static unsigned char lkey_buf[16];
static unsigned char out_buf[16];

int main() {
	AES128_ctx k;

	unhexify(test_text, text_buf, 16);
	unhexify(test_key, key_buf, 16);
	unhexify(test_last_key, lkey_buf, 16);
	unhexify(test_out, out_buf, 16);
	memcpy(orig_buf, text_buf, 16);

	fprintf(stderr, "Testing key schedule!\n");
	AES128.init(k, key_buf);

	assert(!memcmp(k, key_buf, 16));
	fprintf(stderr, "Round key 0 OK!\n");

	assert(!memcmp(k + 160, lkey_buf, 16));
	fprintf(stderr, "Round key 10 OK!\n");

	printf("Testing encryption: ");
	AES128.encrypt(k, text_buf);

	assert(!memcmp(text_buf, out_buf, 16));
	printf("OK!\n");

	printf("Testing decryption: ");
	AES128.decrypt(k, text_buf);

	assert(!memcmp(text_buf, orig_buf, 16));
	printf("OK!\n");
}
