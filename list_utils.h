
#ifndef __list_utils_h_666__
# define __list_utils_h_666__

#define node_link(l, e) do {						\
		typeof((l)) __l_link = (l);				\
		typeof((e)) __e_link = (e);				\
									\
		node_next(__e_link) = NULL;				\
		node_prev(__e_link) = node_list_last(__l_link);		\
		if (node_list_last(__l_link) != NULL)			\
			node_next(node_list_last(__l_link)) = __e_link;	\
		else							\
			node_list_first(__l_link) = __e_link;		\
		node_list_last(__l_link) = __e_link;			\
	} while (0)

#define node_unlink(l, e) do {						\
		typeof((l)) __l_unlink = (l);				\
		typeof((e)) __e_unlink = (e);				\
									\
		if (node_next(__e_unlink) != NULL)			\
			node_prev(node_next(__e_unlink)) = node_prev(__e_unlink); \
		else							\
			node_list_last(__l_unlink) = node_prev(__e_unlink); \
									\
		if (node_prev(__e_unlink) != NULL)			\
			node_next(node_prev(__e_unlink)) = node_next(__e_unlink); \
		else							\
			node_list_first(__l_unlink) = node_next(__e_unlink); \
									\
		node_next(__e_unlink) = NULL;				\
		node_prev(__e_unlink) = NULL;				\
	} while (0)

#define node_is_linked(l, e) (node_list_first((l)) == (e) || node_list_last((l)) == (e) || node_next((e)) != NULL || node_prev((e)) != NULL)

#define node_try_unlink(l, e) do {					\
		typeof((l)) __l_try_unlink = (l);			\
		typeof((e)) __e_try_unlink = (e);			\
									\
		if (node_is_linked(__l_try_unlink, __e_try_unlink))	\
			node_unlink(__l_try_unlink, __e_try_unlink);	\
	} while (0)

#endif
