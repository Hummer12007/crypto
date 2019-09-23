#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "aes.h"
#include "ts.h"
#include "common.h"

int main(int argc, char **argv) {
	uint8_t key[16] = {0x00};
	uint8_t iv[16] = {0x00};
	int plaintext_len;
	AES128_ctx k;
	unsigned char *plain_text = read_input(&plaintext_len);
	uint8_t i;
	enum stream_mode mode;
	struct timespec l, r;
	bool encrypt = true;

	if (plaintext_len % 16) {
		fprintf(stderr, "Length must be a multiple of 16\n");
		return 1;
	}

	if (argc < 2 || !strcasecmp(argv[1], "encrypt"))
		encrypt = true;
	else if (!strcasecmp(argv[1], "decrypt"))
		encrypt = false;

	if (argc < 3 || !strcasecmp(argv[2], "ecb"))
		mode = ECB;
	else if (!strcasecmp(argv[2], "cbc"))
		mode = CBC;
	else if (!strcasecmp(argv[2], "ctr"))
		mode = CTR;

	fprintf(stderr, "keygen:\n");
	AES128.init(k, key);
	parp(k, 176, 16);
	fprintf(stderr, "\n");

	if (encrypt) {
		fprintf(stderr, "encrypting:\n");

		l = ts_gettime(CLOCK_REALTIME);
		streams[mode].encrypt(&AES128, k, plain_text, plaintext_len, iv);
		r = ts_dur(l, ts_gettime(CLOCK_REALTIME));
		fprintf(stderr, "encrypttion took:");
		ts_print(r);

		fwrite(plain_text, plaintext_len, 1, stdout);
	} else {
		fprintf(stderr, "ciphertext:\n");
		parp(plain_text, plaintext_len, 16);

		l = ts_gettime(CLOCK_REALTIME);
		streams[mode].decrypt(&AES128, k, plain_text, plaintext_len, iv);
		r = ts_dur(l, ts_gettime(CLOCK_REALTIME));
		fprintf(stderr, "decryption took:");
		ts_print(r);

		fwrite(plain_text, plaintext_len, 1, stdout);
	}

}
