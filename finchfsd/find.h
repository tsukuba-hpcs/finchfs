#ifndef _FINCH_FIND_H_
#define _FINCH_FIND_H_

typedef enum {
	FIND_ATTR_NAME,
	FIND_ATTR_INO,
	FIND_ATTR_MODE,
	FIND_ATTR_SIZE,
	FIND_ATTR_CHUNK_SIZE,
	FIND_ATTR_MTIM_TVSEC,
	FIND_ATTR_MTIM_TVNSEC,
	FIND_ATTR_CTIM_TVSEC,
	FIND_ATTR_CTIM_TVNSEC,
} find_attr_t;

typedef enum {
	FIND_COMP_EQ,
	FIND_COMP_NE,
	FIND_COMP_LT,
	FIND_COMP_LE,
	FIND_COMP_GT,
	FIND_COMP_GE,
} find_comp_t;

typedef struct find_comp_node {
	find_comp_t op;
	find_attr_t attr;
	void *value;
} find_comp_node_t;

typedef enum {
	FIND_LOGICAL_AND,
	FIND_LOGICAL_OR,
} find_logical_t;

struct find_condition;

typedef struct find_logical_node {
	find_logical_t op;
	struct find_condition *left;
	struct find_condition *right;
} find_logical_node_t;

typedef struct find_condition {
	find_logical_node_t *l;
	find_comp_node_t *c;
} find_condition_t;

find_comp_node_t *build_comp_node(const char *str, char **next);
find_condition_t *build_condition(const char *str, char **next,
				  find_condition_t *left, find_logical_t lop);
void free_condition(find_condition_t *cond);

#endif
