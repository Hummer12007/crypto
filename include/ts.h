#include <time.h>

struct timespec ts_gettime(clock_t clock);

struct timespec ts_add(struct timespec l, struct timespec r);
struct timespec ts_sub(struct timespec l, struct timespec r);
struct timespec ts_dur(struct timespec l, struct timespec r);
int ts_cmp(struct timespec l, struct timespec r);
int ts_cmp_p(struct timespec *l, struct timespec *r);

// timespec to double
double ts_tod(struct timespec spec);

// timespec to allocated string
char *ts_astr(struct timespec spec);

void ts_print(struct timespec spec);

int ts_nstr(struct timespec spec, char *buf, size_t n);
