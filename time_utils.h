
#ifndef __time_utils_h_666__
# define __time_utils_h_666__

# include <time.h>
# include <sys/time.h>
# include "log.h"

void timespec_set(struct timespec *ts, const time_t sec, const long nsec);
void timeval_set(struct timeval *tv, const time_t sec, const suseconds_t usec);

# define timespec_sub(a, b, res) timespec_set((res), (a)->tv_sec - (b)->tv_sec, (a)->tv_nsec - (b)->tv_nsec)
# define timespec_add(a, b, res) timespec_set((res), (a)->tv_sec + (b)->tv_sec, (a)->tv_nsec + (b)->tv_nsec)
# define timespec_to_ms(t) ((t)->tv_sec * 1000 + (t)->tv_nsec / (1000 * 1000))

# define timeval_add_timespec(a, b, res) timeval_set((res), (a)->tv_sec + (b)->tv_sec, (a)->tv_usec + ((b)->tv_nsec / 1000))
# define timeval_sub_timespec(a, b, res) timeval_set((res), (a)->tv_sec - (b)->tv_sec, (a)->tv_usec - ((b)->tv_nsec / 1000))

# define timespec_now(res) do {						\
		int __timespec_now_res;					\
		__timespec_now_res = clock_gettime(CLOCK_MONOTONIC, res); \
		chk(__timespec_now_res == 0);				\
	} while (0)							\

#endif
