#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include "finchfs.h"
#include "path.h"

void
usage(char *progname)
{
	fprintf(stderr, "usage: %s [-m mode] [-p] dir\n", progname);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	char *dir;
	mode_t mode = 0755;
	int recursive = 0;
	int opt;

	while ((opt = getopt(argc, argv, "m:p")) != -1) {
		switch (opt) {
		case 'm':
			mode = strtol(optarg, NULL, 8);
			break;
		case 'p':
			recursive = 1;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage(argv[0]);

	dir = canonical_path(argv[0]);
	if (dir == NULL) {
		fprintf(stderr, "canonical_path failed\n");
		exit(EXIT_FAILURE);
	}

	if (finchfs_init(NULL)) {
		fprintf(stderr, "finchfs_init failed\n");
		exit(EXIT_FAILURE);
	}

	if (!recursive) {
		if (finchfs_mkdir(dir, mode)) {
			fprintf(stderr, "finchfs_mkdir failed: %s\n",
				strerror(errno));
			finchfs_term();
			exit(EXIT_FAILURE);
		}
		finchfs_term();
		exit(EXIT_SUCCESS);
	}

	char name[128];
	char *p = dir;
	int ret = 0;

	while ((p = strchr(p, '/')) != NULL) {
		memcpy(name, dir, p - dir);
		name[p - dir] = '\0';
		++p;
		ret = finchfs_mkdir(name, mode);
		if (ret && errno != EEXIST)
			break;
	}

	if (!(ret && errno != EEXIST))
		ret = finchfs_mkdir(dir, mode);

	if (ret && errno != EEXIST)
		fprintf(stderr, "finchfs_mkdir failed: %s\n", strerror(errno));

	finchfs_term();
	return (ret ? EXIT_FAILURE : EXIT_SUCCESS);
}