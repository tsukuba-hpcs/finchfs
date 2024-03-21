#include <gtest/gtest.h>
#include <thread>
extern "C" {
#include <finchfs.h>
}

TEST(MULTI_TEST, SINGLE)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create_chunk_size("/single", 0, S_IRWXU, (1 << 24));
	EXPECT_EQ(fd, 0);
	char *buf = (char *)malloc((1 << 24));
	ssize_t n;
	for (int i = 0; i < 64; i++) {
		n = finchfs_write(fd, buf, (1 << 24));
		EXPECT_EQ(n, (1 << 24));
	}
	free(buf);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(MULTI_TEST, MULTI)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	std::thread t1([&] {
		int fd;
		fd =
		    finchfs_create_chunk_size("/multi1", 0, S_IRWXU, (1 << 24));
		EXPECT_NE(fd, -1);
		char *buf = (char *)malloc((1 << 24));
		ssize_t n;
		for (int i = 0; i < 32; i++) {
			n = finchfs_write(fd, buf, (1 << 24));
			EXPECT_EQ(n, (1 << 24));
		}
		free(buf);
		finchfs_close(fd);
	});
	std::thread t2([&] {
		int fd;
		fd =
		    finchfs_create_chunk_size("/multi2", 0, S_IRWXU, (1 << 24));
		EXPECT_NE(fd, -1);
		char *buf = (char *)malloc((1 << 24));
		ssize_t n;
		for (int i = 0; i < 32; i++) {
			n = finchfs_write(fd, buf, (1 << 24));
			EXPECT_EQ(n, (1 << 24));
		}
		free(buf);
		finchfs_close(fd);
	});
	t1.join();
	t2.join();
	EXPECT_EQ(finchfs_term(), 0);
}

int
main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
