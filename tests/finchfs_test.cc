#include <stdint.h>
#include <errno.h>
#include <ucp/api/ucp.h>
#include <gtest/gtest.h>
extern "C" {
#include <finchfs.h>
}

TEST(FinchfsTest, Create)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create("/bar", 0, S_IRWXU);
	EXPECT_EQ(fd, 0);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Create2)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create("/baz", 0, S_IRWXU);
	EXPECT_EQ(fd, 0);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Mkdir)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	EXPECT_EQ(finchfs_mkdir("/foo", S_IRWXU), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Mkdir2)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	EXPECT_EQ(finchfs_mkdir("/foo", S_IRWXU), -1);
	EXPECT_EQ(errno, EEXIST);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Mkdir3)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	EXPECT_EQ(finchfs_mkdir("/foo/bar/baz", S_IRWXU), -1);
	EXPECT_EQ(errno, ENOENT);
	EXPECT_EQ(finchfs_term(), 0);
}

static int
path_to_target_hash(const char *path, int div)
{
	long h = 0;
	char *head = strdup(path);
	char *next;
	long n;
	for (char *p = head; *p != '\0'; p = next) {
		n = strtol(p, &next, 10);
		if (next == p) {
			h += *p;
			next++;
			continue;
		}
		h += n;
	}
	free(head);
	return (int)(h % div);
}

TEST(HashTest, Hash)
{
	EXPECT_EQ(path_to_target_hash("/foo1", 8), 4);
	EXPECT_EQ(path_to_target_hash("/foo2", 8), 5);
	EXPECT_EQ(path_to_target_hash("/foo3", 8), 6);
	EXPECT_EQ(path_to_target_hash("/foo4", 8), 7);
	EXPECT_EQ(path_to_target_hash("/foo5", 8), 0);
	EXPECT_EQ(path_to_target_hash("/foo6", 8), 1);
	EXPECT_EQ(path_to_target_hash("/foo7", 8), 2);
	EXPECT_EQ(path_to_target_hash("/foo8", 8), 3);
	EXPECT_EQ(path_to_target_hash("/foo9", 8), 4);
	EXPECT_EQ(path_to_target_hash("/foo10", 8), 5);
}

TEST(HashTest, Hash2)
{
	EXPECT_EQ(path_to_target_hash("/foo01", 8), 4);
	EXPECT_EQ(path_to_target_hash("/foo02", 8), 5);
	EXPECT_EQ(path_to_target_hash("/foo03", 8), 6);
	EXPECT_EQ(path_to_target_hash("/foo04", 8), 7);
	EXPECT_EQ(path_to_target_hash("/foo05", 8), 0);
	EXPECT_EQ(path_to_target_hash("/foo06", 8), 1);
	EXPECT_EQ(path_to_target_hash("/foo07", 8), 2);
	EXPECT_EQ(path_to_target_hash("/foo08", 8), 3);
	EXPECT_EQ(path_to_target_hash("/foo09", 8), 4);
	EXPECT_EQ(path_to_target_hash("/foo10", 8), 5);
}

int
main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
