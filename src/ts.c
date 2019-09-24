#include <stdio.h>
#include <stdlib.h>
#include <time.h>

struct timespec ts_gettime(clock_t clock) {
	struct timespec res;
	clock_gettime(clock, &res);
	return res;
}

struct timespec ts_add(struct timespec l, struct timespec r) {
	struct timespec res = {
		.tv_sec = l.tv_sec + r.tv_sec,
		.tv_nsec = l.tv_nsec + r.tv_nsec,
	};
	if (res.tv_nsec >= 1000000000) {
		res.tv_nsec -= 1000000000;
		res.tv_sec++;
	}
	return res;
}

struct timespec ts_sub(struct timespec l, struct timespec r) {
	struct timespec res = {
		.tv_sec = l.tv_sec - r.tv_sec,
		.tv_nsec = l.tv_nsec - r.tv_nsec,
	};
	if (res.tv_nsec < 0) {
		res.tv_nsec += 1000000000;
		res.tv_sec--;
	}
	return res;
}

int ts_cmp(struct timespec l, struct timespec r) {
	if (l.tv_sec > r.tv_sec)
		return 1;
	if (l.tv_sec < r.tv_sec)
		return -1;
	return l.tv_nsec > r.tv_nsec ? -1 : (l.tv_nsec > r.tv_nsec);
}

int ts_cmp_p(struct timespec *l, struct timespec *r) {
	if (l->tv_sec > r->tv_sec)
		return 1;
	if (l->tv_sec < r->tv_sec)
		return -1;
	return l->tv_nsec > r->tv_nsec ? -1 : (l->tv_nsec > r->tv_nsec);
}

struct timespec ts_dur(struct timespec l, struct timespec r) {
	if (ts_cmp(l, r) > 0)
		return ts_sub(l, r);
	return ts_sub(r, l);
}

double ts_tod(struct timespec spec) {
	return spec.tv_sec + 1e-9 * spec.tv_nsec;
}

char *ts_astr(struct timespec spec) {
	char *ret = calloc(32, 1);
	if (spec.tv_nsec >= 1000000000)
		spec.tv_nsec %= 1000000000;
	snprintf(ret, 31, "%ld.%09ld", spec.tv_sec, spec.tv_nsec);
	return ret;
}

void ts_print(struct timespec spec) {
	if (spec.tv_nsec >= 1000000000)
		spec.tv_nsec %= 1000000000;
	fprintf(stderr, "%ld.%09ld\n", spec.tv_sec, spec.tv_nsec);
}
