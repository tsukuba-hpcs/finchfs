#include <stdint.h>
#include <gtest/gtest.h>
extern "C" {
#include <finchfs.h>
}

TEST(FinchfsTest, OpenClose)
{
	int fd;
	fd = finchfs_open("/hello_world", 0);
	EXPECT_EQ(fd, 0);
	finchfs_close(fd);
}

int
main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
