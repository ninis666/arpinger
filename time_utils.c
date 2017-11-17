
#include "time_utils.h"

void timespec_set(struct timespec *ts, const time_t sec, const long nsec)
{
	const long nsec_per_sec = (1 * 1000 * 1000 * 1000);

	ts->tv_sec = sec;
	ts->tv_nsec = nsec;

	while (ts->tv_nsec >= nsec_per_sec) {
		ts->tv_nsec -= nsec_per_sec;
		++ts->tv_sec;
	}

	while (ts->tv_nsec < 0) {
		ts->tv_nsec += nsec_per_sec;
		--ts->tv_sec;
	}
}

void timeval_set(struct timeval *tv, const time_t sec, const suseconds_t usec)
{
	const suseconds_t usec_per_sec = (1 * 1000 * 1000);

	tv->tv_sec = sec;
	tv->tv_usec = usec;

	while (tv->tv_usec >= usec_per_sec) {
		tv->tv_usec -= usec_per_sec;
		++tv->tv_sec;
	}

	while (tv->tv_usec < 0) {
		tv->tv_usec += usec_per_sec;
		--tv->tv_sec;
	}
}
