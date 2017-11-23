
#ifndef __err_h_666__
# define __err_h_666__

# include <stdio.h>
# include <stdlib.h>
# include <errno.h>

# ifndef unlikely
#  define unlikely(x) __builtin_expect ((x), 0)
# endif

# ifndef ARP_DEBUG
#  define ARP_DEBUG 0
# endif

# define msg(pfx, ...) do {						\
		const int err = errno;					\
		fprintf(stderr, pfx "%s:%d ", __FILE__, __LINE__);	\
		errno = err;						\
		fprintf(stderr, __VA_ARGS__);				\
	} while (0)

# define err(...) msg("ERR ", __VA_ARGS__)
# define wrn(...) msg("WRN ", __VA_ARGS__)
# define die(...) do { msg("DIE ", __VA_ARGS__); abort(); } while (0)

#define is_vrb() (ARP_DEBUG > 1)
#define is_dbg() (ARP_DEBUG > 0)

# define dbg(...) do {					\
		if (is_dbg())				\
			msg("DBG ", __VA_ARGS__);	\
	} while (0)

# define vrb(...) do {					\
		if (is_vrb())				\
			msg("VRB ", __VA_ARGS__);	\
	} while (0)

# if ((defined ARP_CHECK) && (ARP_CHECK > 0))
#  define chk(cond) do {				\
		if (unlikely(!(cond)))			\
			die(# cond "\n");		\
	} while (0)
# else
#  define chk(...) do { } while (0)
# endif

#endif
