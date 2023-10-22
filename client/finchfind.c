#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <fnmatch.h>
#include <getopt.h>
#include "finchfs.h"

static struct option options[] = {{"name", required_argument, NULL, 'n'},
				  {"size", required_argument, NULL, 's'},
				  {"newer", required_argument, NULL, 'N'},
				  {"type", required_argument, NULL, 't'},
				  {0, 0, 0, 0}};

static void
usage(void)
{
	fprintf(stderr, "usage: finchfind [-qv] [dir] [-name pat] "
			"[-size size] [-newer file]\n\t[-type type]\n");
	exit(EXIT_FAILURE);
}

static struct {
	char *name, type, *newer, *size;
	struct stat newer_sb;
	int quiet, verbose;
	long size_prefix, size_unit, size_count;
} opt;

static void
parse_size(char *str_size)
{
	char *s = str_size;
	long prefix = 0, count = 0, unit = 0;

	switch (*s) {
	case '-':
		prefix = -1;
		++s;
		break;
	case '+':
		prefix = 1;
		++s;
		break;
	}
	while (*s >= '0' && *s <= '9')
		count = 10 * count + (*s++ - '0');

	switch (*s) {
	case 'b':
		unit = 512;
		++s;
		break;
	case 'c':
		unit = 1;
		++s;
		break;
	case 'w':
		unit = 2;
		++s;
		break;
	case 'k':
		unit = 1024;
		++s;
		break;
	case 'M':
		unit = 1024 * 1024;
		++s;
		break;
	case 'G':
		unit = 1024 * 1024 * 1024;
		++s;
		break;
	case '\0':
		unit = 512;
		break;
	}
	if (*s) {
		fprintf(stderr, "invalid size: %s\n", str_size);
		exit(EXIT_FAILURE);
	}
	opt.size_prefix = prefix;
	opt.size_count = count;
	opt.size_unit = unit;
}

void
append_and_cond(char *query, char *c)
{
	if (query[0] != '\0')
		strcat(query, " && ");
	strcat(query, c);
}

int
main(int argc, char *argv[])
{
	int c;
	while ((c = getopt_long_only(argc, argv, "qv", options, NULL)) != -1) {
		switch (c) {
		case 'n':
			opt.name = optarg;
			break;
		case 'N':
			opt.newer = optarg;
			break;
		case 'q':
			opt.quiet = 1;
			break;
		case 's':
			opt.size = optarg;
			parse_size(opt.size);
			break;
		case 't':
			opt.type = optarg[0];
			break;
		case 'v':
			opt.verbose++;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage();
		exit(EXIT_FAILURE);
	}

	if (finchfs_init(NULL)) {
		fprintf(stderr, "finchfs_init failed\n");
		exit(EXIT_FAILURE);
	}

	char query[1024];
	query[0] = '\0';

	if (opt.newer) {
		if (stat(opt.newer, &opt.newer_sb)) {
			fprintf(stderr, "stat failed: %s\n", opt.newer);
			exit(EXIT_FAILURE);
		}
		char c[1024];
		sprintf(c,
			"mtim.tv_sec > %ld || (mtim.tv_sec == %ld && "
			"mtim.tv_nsec > %ld)",
			opt.newer_sb.st_mtim.tv_sec,
			opt.newer_sb.st_mtim.tv_sec,
			opt.newer_sb.st_mtim.tv_nsec);

		append_and_cond(query, c);
	}

	if (opt.name) {
		char c[1024];
		sprintf(c, "name == \"%s\"", opt.name);
		append_and_cond(query, c);
	}

	if (opt.size) {
		char c[1024];
		switch (opt.size_prefix) {
		case -1:
			sprintf(c, "size < %ld",
				opt.size_count * opt.size_unit);
			break;
		case 0:
			sprintf(c, "size == %ld",
				opt.size_count * opt.size_unit);
			break;
		case 1:
			sprintf(c, "size > %ld",
				opt.size_count * opt.size_unit);
			break;
		}
		append_and_cond(query, c);
	}

	if (opt.type) {
		char c[1024];
		switch (opt.type) {
		case 'd':
			sprintf(c, "mode & 0040000");
			break;
		case 'f':
			sprintf(c, "mode & 0100000");
			break;
		}
		append_and_cond(query, c);
	}

	if (opt.verbose) {
		printf("query: %s\n", query);
	}

	struct finchfs_find_param param = {
	    .flag = FINCHFS_FIND_FLAG_RECURSIVE,
	    .total_nentries = 0,
	    .match_nentries = 0,
	};

	if (finchfs_find(argv[0], query, &param, NULL, NULL)) {
		fprintf(stderr, "finchfs_find failed\n");
		finchfs_term();
		exit(EXIT_FAILURE);
	}

	printf("MATCHED %lu/%lu\n", param.match_nentries, param.total_nentries);

	finchfs_term();

	return (0);
}