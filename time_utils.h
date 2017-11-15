
#ifndef __time_utils_h_666__
# define __time_utils_h_666__

# include <time.h>

void timspec_set(struct timespec *ts, const time_t sec, const long nsec);

# define timespec_sub(a, b, res) timspec_set((res), (a)->tv_sec - (b)->tv_sec, (a)->tv_nsec - (b)->tv_nsec)
# define timespec_add(a, b, res) timspec_set((res), (a)->tv_sec + (b)->tv_sec, (a)->tv_nsec + (b)->tv_nsec)
# define timespec_to_ms(t) ((t)->tv_sec * 1000 + (t)->tv_nsec / (1000 * 1000))

#endif
