
#ifndef __err_h_666__
# define __err_h_666__

# include <stdio.h>
# include <errno.h>

#define msg(pfx, ...) do {						\
		const int err = errno;					\
		fprintf(stderr, pfx "%s:%d ", __FILE__, __LINE__);	\
		errno = err;						\
		fprintf(stderr, __VA_ARGS__);				\
	} while (0)

#define err(...) msg("ERR", __VA_ARGS__)
#define wrn(...) msg("WRN", __VA_ARGS__)
#define die(...) do { msg("DIE", __VA_ARGS__); abort(); } while (0)

#endif
