#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include "log.h"
#include "find.h"

char *
next_token(char *p)
{
	while (*p && *p == ' ') {
		p++;
	}
	if (*p == '\0') {
		return (NULL);
	}
	return (p);
}

static find_attr_t
get_attr(char *str, char **next)
{
	if (strncmp("name", str, 4) == 0) {
		*next = str + 4;
		return (FIND_ATTR_NAME);
	}
	if (strncmp("ino", str, 3) == 0) {
		*next = str + 3;
		return (FIND_ATTR_INO);
	}
	if (strncmp("mode", str, 4) == 0) {
		*next = str + 4;
		return (FIND_ATTR_MODE);
	}
	if (strncmp("size", str, 4) == 0) {
		*next = str + 4;
		return (FIND_ATTR_SIZE);
	}
	if (strncmp("chunk_size", str, 10) == 0) {
		*next = str + 10;
		return (FIND_ATTR_CHUNK_SIZE);
	}
	if (strncmp("mtim.tv_sec", str, 11) == 0) {
		*next = str + 11;
		return (FIND_ATTR_MTIM_TVSEC);
	}
	if (strncmp("mtim.tv_nsec", str, 12) == 0) {
		*next = str + 12;
		return (FIND_ATTR_MTIM_TVNSEC);
	}
	if (strncmp("ctim.tv_sec", str, 11) == 0) {
		*next = str + 11;
		return (FIND_ATTR_CTIM_TVSEC);
	}
	if (strncmp("ctim.tv_nsec", str, 12) == 0) {
		*next = str + 12;
		return (FIND_ATTR_CTIM_TVNSEC);
	}
	log_error("Invalid attr: %s", str);
	return (-1);
}

static find_comp_t
get_comp_op(char *str, char **next)
{
	if (strncmp("==", str, 2) == 0) {
		*next = str + 2;
		return (FIND_COMP_EQ);
	}
	if (strncmp("!=", str, 2) == 0) {
		*next = str + 2;
		return (FIND_COMP_NE);
	}
	if (strncmp("<=", str, 2) == 0) {
		*next = str + 2;
		return (FIND_COMP_LE);
	}
	if (strncmp(">=", str, 2) == 0) {
		*next = str + 2;
		return (FIND_COMP_GE);
	}
	if (strncmp("<", str, 1) == 0) {
		*next = str + 1;
		return (FIND_COMP_LT);
	}
	if (strncmp(">", str, 1) == 0) {
		*next = str + 1;
		return (FIND_COMP_GT);
	}
	log_error("Invalid comparison operator: %s", str);
	return (-1);
}

static char *
get_comp_name(char *str)
{
	char *p = str;
	int esc = 0;
	if (*p != '"') {
		return (str);
	}
	p++;
	while (*p != '\0') {
		if (esc) {
			esc = 0;
			p++;
			continue;
		}
		if (*p == '\\') {
			esc = 1;
			p++;
			continue;
		}
		if (*p == '"') {
			return (p + 1);
		}
		p++;
	}
	return (str);
}

find_comp_node_t *
build_comp_node(const char *str, char **next)
{
	char *t = next_token(str);
	if (t == NULL) {
		return (NULL);
	}
	find_attr_t attr;
	attr = get_attr(t, &t);
	if (attr < 0) {
		return (NULL);
	}
	t = next_token(t);
	if (t == NULL) {
		return (NULL);
	}
	find_comp_t op;
	op = get_comp_op(t, &t);
	if (op < 0) {
		return (NULL);
	}
	t = next_token(t);
	if (t == NULL) {
		return (NULL);
	}
	find_comp_node_t *node = malloc(sizeof(find_comp_node_t));
	node->attr = attr;
	node->op = op;
	switch (attr) {
	case FIND_ATTR_NAME:
		if (op != FIND_COMP_EQ) {
			free(node);
			return (NULL);
		}
		*next = get_comp_name(t);
		if (*next == t) {
			free(node);
			return (NULL);
		}
		node->value = strndup(t + 1, *next - t - 2);
		break;
	case FIND_ATTR_INO:
	case FIND_ATTR_SIZE:
	case FIND_ATTR_CHUNK_SIZE:
		node->value = malloc(sizeof(uint64_t));
		*(uint64_t *)node->value = strtoull(t, next, 10);
		if (t == *next) {
			free(node->value);
			free(node);
			return (NULL);
		}
		break;
	case FIND_ATTR_MODE:
		node->value = malloc(sizeof(mode_t));
		*(mode_t *)node->value = strtol(t, next, 10);
		if (t == *next) {
			free(node->value);
			free(node);
			return (NULL);
		}
		break;
	case FIND_ATTR_MTIM_TVSEC:
	case FIND_ATTR_CTIM_TVSEC:
		node->value = malloc(sizeof(time_t));
		*(time_t *)node->value = strtol(t, next, 10);
		if (t == *next) {
			free(node->value);
			free(node);
			return (NULL);
		}
		break;
	case FIND_ATTR_MTIM_TVNSEC:
	case FIND_ATTR_CTIM_TVNSEC:
		node->value = malloc(sizeof(int64_t));
		*(int64_t *)node->value = strtol(t, next, 10);
		if (t == *next) {
			free(node->value);
			free(node);
			return (NULL);
		}
		break;
	}
	return (node);
}

static find_logical_t
get_logical_op(char *str, char **next)
{
	if (strncmp("&&", str, 2) == 0) {
		*next = str + 2;
		return (FIND_LOGICAL_AND);
	}
	if (strncmp("||", str, 2) == 0) {
		*next = str + 2;
		return (FIND_LOGICAL_OR);
	}
	return (-1);
}

static get_left_parenthesis(char *str, char **next)
{
	if (strncmp("(", str, 1) == 0) {
		*next = str + 1;
		return (1);
	}
	return (0);
}

static get_right_parenthesis(char *str, char **next)
{
	if (strncmp(")", str, 1) == 0) {
		*next = str + 1;
		return (1);
	}
	return (0);
}

find_condition_t *
build_condition(const char *str, char **next, find_condition_t *left,
		find_logical_t lop)
{
	log_debug("build_condition: %s", str);
	char *t = next_token(str);
	if (t == NULL) {
		*next = NULL;
		return (left);
	}
	find_comp_node_t *c = build_comp_node(t, &t);
	if (c == NULL) {
		*next = NULL;
		return (NULL);
	}
	t = next_token(t);
	if (t == NULL || get_right_parenthesis(t, &t)) {
		*next = (t == NULL) ? NULL : t - 1;
		if (left != NULL) {
			find_condition_t *right =
			    malloc(sizeof(find_condition_t));
			find_condition_t *root =
			    malloc(sizeof(find_condition_t));
			right->c = c;
			root->c = NULL;
			root->l = malloc(sizeof(find_logical_node_t));
			root->l->op = lop;
			root->l->left = left;
			root->l->right = right;
			return (root);
		}
		find_condition_t *root = malloc(sizeof(find_condition_t));
		root->c = c;
		root->l = NULL;
		return (root);
	}
	find_logical_t op;
	op = get_logical_op(t, &t);
	if (op < 0) {
		*next = NULL;
		return (NULL);
	}
	t = next_token(t);
	if (t == NULL) {
		*next = NULL;
		return (NULL);
	}
	if (get_left_parenthesis(t, &t)) {
		log_debug("get_left_parenthesis(t, &t); t=%s", t);
		find_condition_t *right =
		    build_condition(t, &t, NULL, FIND_LOGICAL_AND);
		log_debug("ret from build_condition: str=%s, t=%s", str, t);
		if (right == NULL) {
			*next = NULL;
			return (NULL);
		}
		t = next_token(t);
		if (t == NULL) {
			*next = NULL;
			return (NULL);
		}
		if (!get_right_parenthesis(t, &t)) {
			*next = NULL;
			return (NULL);
		}
		*next = t;
		if (left == NULL) {
			find_condition_t *lroot =
			    malloc(sizeof(find_condition_t));
			lroot->c = c;
			lroot->l = NULL;
			find_condition_t *root =
			    malloc(sizeof(find_condition_t));
			root->c = NULL;
			root->l = malloc(sizeof(find_logical_node_t));
			root->l->op = op;
			root->l->left = lroot;
			root->l->right = right;
			t = next_token(t);
			if (t == NULL || get_right_parenthesis(t, &t)) {
				*next = (t == NULL) ? NULL : t - 1;
				return (root);
			}
			op = get_logical_op(t, &t);
			if (op < 0) {
				*next = NULL;
				return (NULL);
			}
			*next = t;
			return (build_condition(t, next, root, op));
		}
		find_condition_t *lroot = malloc(sizeof(find_condition_t));
		lroot->c = NULL;
		lroot->l = malloc(sizeof(find_logical_node_t));
		lroot->l->op = lop;
		lroot->l->left = left;
		lroot->l->right = malloc(sizeof(find_condition_t));
		lroot->l->right->c = c;
		lroot->l->right->l = NULL;
		find_condition_t *root = malloc(sizeof(find_condition_t));
		root->c = NULL;
		root->l = malloc(sizeof(find_logical_node_t));
		root->l->op = op;
		root->l->left = lroot;
		root->l->right = right;
		t = next_token(t);
		if (t == NULL || get_right_parenthesis(t, &t)) {
			*next = (t == NULL) ? NULL : t - 1;
			return (root);
		}
		op = get_logical_op(t, &t);
		if (op < 0) {
			*next = NULL;
			return (NULL);
		}
		*next = t;
		return (build_condition(t, next, root, op));
	}
	if (left == NULL) {
		find_condition_t *root = malloc(sizeof(find_condition_t));
		root->c = c;
		root->l = NULL;
		return (build_condition(t, next, root, op));
	}
	find_condition_t *root = malloc(sizeof(find_condition_t));
	root->c = NULL;
	root->l->op = lop;
	root->l->left = left;
	root->l->right = malloc(sizeof(find_condition_t));
	root->l->right->c = c;
	root->l->right->l = NULL;
	*next = t;
	return (build_condition(t, next, root, op));
}
