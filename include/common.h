#include <stdio.h>

#define parp(a, N, s) do { for (int __i = 0; __i < N; ++__i) fprintf(stderr, (__i % s == s - 1) ? "%02x\n" : "%02x", (a)[__i]);} while (0)

#define par(a, N) parp(a, N, N)

#define pas(a) par(a, sizeof(a) / sizeof(a[0]))
#define pasp(a, s) parp(a, sizeof(a) / sizeof(a[0]), s)

unsigned char *read_file(FILE *, int *);
#define read_input(i) read_file(stdin, i)
