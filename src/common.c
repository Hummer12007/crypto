#include <stdlib.h>
#include "common.h"

unsigned char *read_file(FILE *f, int *len) {
	size_t n = 128, c = 0;
	unsigned char *buf = calloc(n + 1, 1);
	while (!feof(f)) {
		c += fread(buf + c, 1, n - c, f);
		buf[c] = 0;
		if (c == n)
			buf = realloc(buf, (n *= 2) + 1);
	}
	*len = c;
	return buf;
}

