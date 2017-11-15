
#include "time_utils.h"

void timspec_set(struct timespec *ts, const time_t sec, const long nsec)
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
