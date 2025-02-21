#include <stdint.h>
#include <errno.h>
#include <ucp/api/ucp.h>
#include <gtest/gtest.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/mman.h>
extern "C" {
#include <finchfs.h>
}

TEST(FinchfsTest, Create)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create("/bar", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Create2)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create("/baz", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Open)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_open("/bar", O_RDWR);
	EXPECT_EQ(fd, 0);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Open2)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_open("/baz", O_RDWR);
	EXPECT_EQ(fd, 0);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Open3)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd1, fd2;
	fd1 = finchfs_open("/bar", O_RDWR);
	EXPECT_EQ(fd1, 0);
	fd2 = finchfs_open("/baz", O_RDWR);
	EXPECT_EQ(fd2, 1);
	finchfs_close(fd1);
	finchfs_close(fd2);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Open4)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd1, fd2;
	fd1 = finchfs_open("/bar", O_RDWR);
	EXPECT_EQ(fd1, 0);
	finchfs_close(fd1);
	fd2 = finchfs_open("/baz", O_RDWR);
	EXPECT_EQ(fd2, 0);
	finchfs_close(fd2);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Open_Dir)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_open("/", O_RDONLY | O_DIRECTORY);
	EXPECT_EQ(fd, 0);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Open_Dir_2)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	EXPECT_EQ(finchfs_mkdir("/open_dir", 0777), 0);
	int fd;
	fd = finchfs_open("/open_dir", O_RDONLY | O_DIRECTORY);
	EXPECT_EQ(fd, 0);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Write)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create("/write1", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	char buf[1024];
	ssize_t n;
	n = finchfs_write(fd, buf, sizeof(buf));
	EXPECT_EQ(n, sizeof(buf));
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Write2)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create_chunk_size("/write2", O_RDWR, S_IRWXU, 128);
	EXPECT_EQ(fd, 0);
	char buf[1024];
	ssize_t n;
	n = finchfs_write(fd, buf, sizeof(buf));
	EXPECT_EQ(n, sizeof(buf));
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Write3)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create_chunk_size("/write3", O_RDWR, S_IRWXU, 128);
	EXPECT_EQ(fd, 0);
	char buf[777];
	ssize_t n;
	n = finchfs_write(fd, buf, sizeof(buf));
	EXPECT_EQ(n, sizeof(buf));
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Write4)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create_chunk_size("/write4", O_RDWR, S_IRWXU, 128);
	EXPECT_EQ(fd, 0);
	char buf[100];
	ssize_t n;
	for (int i = 0; i < 8; i++) {
		n = finchfs_write(fd, buf, sizeof(buf));
		EXPECT_EQ(n, sizeof(buf));
	}
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Write5)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create_chunk_size("/write5", O_RDWR, S_IRWXU, (1 << 24));
	EXPECT_EQ(fd, 0);
	char *buf = (char *)malloc((1 << 24));
	ssize_t n;
	n = finchfs_write(fd, buf, (1 << 24));
	EXPECT_EQ(n, (1 << 24));
	free(buf);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

static void
rnd_fill(char *buf, size_t size)
{
	for (size_t i = 0; i < size; i++) {
		buf[i] = rand() % 256;
	}
}

TEST(FinchfsTest, Read)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create("/read1", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	char buf[1024], buf2[1024];
	rnd_fill(buf, sizeof(buf));
	ssize_t n;
	n = finchfs_write(fd, buf, sizeof(buf));
	EXPECT_EQ(n, sizeof(buf));
	finchfs_close(fd);
	fd = finchfs_open("/read1", O_RDWR);
	EXPECT_EQ(fd, 0);
	n = finchfs_read(fd, buf2, sizeof(buf2));
	EXPECT_EQ(n, sizeof(buf2));
	EXPECT_TRUE(memcmp(buf, buf2, sizeof(buf2)) == 0);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Read2)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create_chunk_size("/read2", O_RDWR, S_IRWXU, (1 << 24));
	EXPECT_EQ(fd, 0);
	char *buf;
	char *buf2;
	buf = (char *)malloc((1 << 24));
	buf2 = (char *)malloc((1 << 24));
	rnd_fill(buf, 1 << 24);
	ssize_t n;
	n = finchfs_write(fd, buf, (1 << 24));
	EXPECT_EQ(n, 1 << 24);
	finchfs_close(fd);
	fd = finchfs_open("/read2", O_RDWR);
	EXPECT_EQ(fd, 0);
	n = finchfs_read(fd, buf2, (1 << 24));
	EXPECT_EQ(n, (1 << 24));
	EXPECT_TRUE(memcmp(buf, buf2, (1 << 24)) == 0);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Read3)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create_chunk_size("/read3", O_RDWR, S_IRWXU, 128);
	EXPECT_EQ(fd, 0);
	char buf[1024];
	char buf2[1024];
	rnd_fill(buf, sizeof(buf));
	ssize_t n;
	n = finchfs_write(fd, buf, sizeof(buf));
	EXPECT_EQ(n, sizeof(buf));
	finchfs_close(fd);
	fd = finchfs_open("/read3", O_RDWR);
	EXPECT_EQ(fd, 0);
	for (int i = 0; i < 8; i++) {
		n = finchfs_read(fd, buf2, 100);
		EXPECT_EQ(n, 100);
		EXPECT_TRUE(memcmp(buf + i * 100, buf2, 100) == 0);
	}
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Read4)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create_chunk_size("/read4", O_RDWR, S_IRWXU, 128);
	EXPECT_EQ(fd, 0);
	char buf[200];
	rnd_fill(buf, sizeof(buf));
	ssize_t n;
	n = finchfs_write(fd, buf, sizeof(buf));
	EXPECT_EQ(n, sizeof(buf));
	finchfs_close(fd);
	fd = finchfs_open("/read4", O_RDONLY);
	EXPECT_EQ(fd, 0);
	char buf2[200];
	n = finchfs_read(fd, buf2, 128);
	EXPECT_EQ(n, 128);
	n = finchfs_read(fd, buf2, 128);
	EXPECT_EQ(n, 200-128);
	n = finchfs_read(fd, buf2, 128);
	EXPECT_EQ(n, 0);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Create_O_TRUNC)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create("/trunc1", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	char buf[1024];
	rnd_fill(buf, sizeof(buf));
	ssize_t n;
	n = finchfs_write(fd, buf, sizeof(buf));
	EXPECT_EQ(n, sizeof(buf));
	finchfs_close(fd);
	fd = finchfs_create("/trunc1", O_TRUNC | O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	n = finchfs_read(fd, buf, sizeof(buf));
	EXPECT_EQ(n, 0);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Open_O_TRUNC)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create("/trunc2", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	char buf[1024];
	rnd_fill(buf, sizeof(buf));
	ssize_t n;
	n = finchfs_write(fd, buf, sizeof(buf));
	EXPECT_EQ(n, sizeof(buf));
	finchfs_close(fd);
	fd = finchfs_open("/trunc2", O_TRUNC | O_RDWR);
	EXPECT_EQ(fd, 0);
	n = finchfs_read(fd, buf, sizeof(buf));
	EXPECT_EQ(n, 0);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Unlink)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create("/unlink1", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_unlink("/unlink1"), 0);
	fd = finchfs_open("/unlink1", 0);
	EXPECT_EQ(fd, -1);
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

TEST(FinchfsTest, Rmdir)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	EXPECT_EQ(finchfs_mkdir("/rmdir1", S_IRWXU), 0);
	int fd;
	fd = finchfs_create("/rmdir1/file1", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_rmdir("/rmdir1"), 0);
	fd = finchfs_open("/rmdir1/file1", O_RDWR);
	EXPECT_EQ(fd, -1);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Rename)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	EXPECT_EQ(finchfs_mkdir("/rename", S_IRWXU), 0);
	char buf[128];
	rnd_fill(buf, sizeof(buf));
	fd = finchfs_create("/rename_file", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	ssize_t n;
	n = finchfs_write(fd, buf, sizeof(buf));
	EXPECT_EQ(n, sizeof(buf));
	finchfs_close(fd);
	EXPECT_EQ(finchfs_rename("/rename_file", "/rename/rename_file"), 0);
	fd = finchfs_open("/rename/rename_file", O_RDWR);
	EXPECT_EQ(fd, 0);
	char buf2[128];
	n = finchfs_read(fd, buf2, sizeof(buf2));
	EXPECT_EQ(n, sizeof(buf2));
	EXPECT_TRUE(memcmp(buf, buf2, sizeof(buf2)) == 0);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, RenameDir)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	EXPECT_EQ(finchfs_mkdir("/XXX", S_IRWXU), 0);
	EXPECT_EQ(finchfs_mkdir("/XXX/YYY", S_IRWXU), 0);
	int fd;
	fd = finchfs_create("/XXX/YYY/file1", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_rename("/XXX/YYY", "/XXX/ZZZ"), 0);
	fd = finchfs_open("/XXX/ZZZ/file1", O_RDWR);
	EXPECT_EQ(fd, 0);
	finchfs_close(fd);
	EXPECT_EQ(finchfs_rmdir("/XXX/ZZZ"), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Stat)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	char buf[128];
	rnd_fill(buf, sizeof(buf));
	fd = finchfs_create("/stat1", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	ssize_t n;
	n = finchfs_write(fd, buf, sizeof(buf));
	EXPECT_EQ(n, sizeof(buf));
	finchfs_close(fd);
	struct stat st;
	EXPECT_EQ(finchfs_stat("/stat1", &st), 0);
	EXPECT_EQ(st.st_size, sizeof(buf));
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Stat2)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	char buf[1000];
	rnd_fill(buf, sizeof(buf));
	fd = finchfs_create_chunk_size("/stat2", O_RDWR, S_IRWXU, 128);
	EXPECT_EQ(fd, 0);
	ssize_t n;
	n = finchfs_write(fd, buf, sizeof(buf));
	EXPECT_EQ(n, sizeof(buf));
	finchfs_close(fd);
	struct stat st;
	EXPECT_EQ(finchfs_stat("/stat2", &st), 0);
	EXPECT_EQ(st.st_size, sizeof(buf));
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Fstat)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	char buf[128];
	rnd_fill(buf, sizeof(buf));
	fd = finchfs_create("/fstat1", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	ssize_t n;
	n = finchfs_write(fd, buf, sizeof(buf));
	EXPECT_EQ(n, sizeof(buf));
	EXPECT_EQ(finchfs_fsync(fd), 0);
	struct stat st;
	EXPECT_EQ(finchfs_fstat(fd, &st), 0);
	EXPECT_EQ(st.st_size, sizeof(buf));
	finchfs_close(fd);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, SingleSharedFile)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd1;
	char buf1[1000];
	int fd2;
	char buf2[1000];
	fd1 = finchfs_create("/single_shared", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd1, 0);
	fd2 = finchfs_create("/single_shared", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd2, 1);
	ssize_t n;
	rnd_fill(buf1, sizeof(buf1));
	n = finchfs_write(fd1, buf1, sizeof(buf1));
	EXPECT_EQ(n, sizeof(buf1));
	n = finchfs_read(fd2, buf2, sizeof(buf2));
	EXPECT_EQ(n, sizeof(buf2));
	EXPECT_TRUE(memcmp(buf1, buf2, sizeof(buf2)) == 0);
	finchfs_close(fd1);
	finchfs_close(fd2);
	EXPECT_EQ(finchfs_term(), 0);
}

static void
filler1(void *arg, const char *path, const struct stat *st)
{
	int *filler1_called = (int *)arg;
	EXPECT_STREQ(path, "file1");
	*filler1_called = *filler1_called + 1;
}

TEST(FinchfsTest, Readdir)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	EXPECT_EQ(finchfs_mkdir("/readdir1", S_IRWXU), 0);
	int fd;
	fd = finchfs_create("/readdir1/file1", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	finchfs_close(fd);
	int filler1_called = 0;
	EXPECT_EQ(finchfs_readdir("/readdir1", &filler1_called, filler1), 0);
	EXPECT_EQ(filler1_called, 1);
	EXPECT_EQ(finchfs_term(), 0);
}

static void
filler2(void *arg, const char *path, const struct stat *st)
{
	int *filler2_called = (int *)arg;
	EXPECT_STREQ(path, "dir");
	*filler2_called = *filler2_called + 1;
}

TEST(FinchfsTest, Readdir2)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	EXPECT_EQ(finchfs_mkdir("/readdir2", S_IRWXU), 0);
	EXPECT_EQ(finchfs_mkdir("/readdir2/dir", S_IRWXU), 0);
	int filler2_called = 0;
	EXPECT_EQ(finchfs_readdir("/readdir2", &filler2_called, filler2), 0);
	EXPECT_EQ(filler2_called, 1);
	EXPECT_EQ(finchfs_term(), 0);
}

static void
filler3(void *arg, const char *path, const struct stat *st)
{
	int *filler3_called = (int *)arg;
	*filler3_called = *filler3_called + 1;
}

TEST(FinchfsTest, Readdir3)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	EXPECT_EQ(finchfs_mkdir("/readdir3", S_IRWXU), 0);
	for (int i = 0; i < 10000; i++) {
		char path[128];
		sprintf(path, "/readdir3/%d", i);
		int fd;
		fd = finchfs_create(path, O_RDWR, S_IRWXU);
		EXPECT_EQ(fd, 0);
		finchfs_close(fd);
	}
	int filler3_called = 0;
	EXPECT_EQ(finchfs_readdir("/readdir3", &filler3_called, filler3), 0);
	EXPECT_EQ(filler3_called, 10000);
	EXPECT_EQ(finchfs_term(), 0);
}

static void
filler_find(void *arg, const char *path)
{
	int *filler_find_called = (int *)arg;
	*filler_find_called = *filler_find_called + 1;
}

TEST(FinchfsTest, FIND)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	EXPECT_EQ(finchfs_mkdir("/find", S_IRWXU), 0);
	for (int i = 0; i < 100; i++) {
		char path[128];
		sprintf(path, "/find/%d", i);
		int fd;
		fd = finchfs_create(path, O_RDWR, S_IRWXU);
		EXPECT_EQ(fd, 0);
		finchfs_close(fd);
	}
	int filler_find_called = 0;
	finchfs_find_param param = {
	    .flag = FINCHFS_FIND_FLAG_RECURSIVE | FINCHFS_FIND_FLAG_RETURN_PATH,
	};
	EXPECT_EQ(finchfs_find("/find", "name == \"*\"", &param,
			       &filler_find_called, filler_find),
		  0);
	EXPECT_EQ(filler_find_called, 101);
	EXPECT_EQ(param.total_nentries, 101);
	EXPECT_EQ(param.match_nentries, 101);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, FIND2)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	EXPECT_EQ(finchfs_mkdir("/find2", S_IRWXU), 0);
	for (int i = 0; i < 10000; i++) {
		char path[128];
		sprintf(path, "/find2/%d", i);
		int fd;
		fd = finchfs_create(path, O_RDWR, S_IRWXU);
		EXPECT_EQ(fd, 0);
		finchfs_close(fd);
	}
	int filler_find_called = 0;
	finchfs_find_param param = {
	    .flag = FINCHFS_FIND_FLAG_RECURSIVE | FINCHFS_FIND_FLAG_RETURN_PATH,
	};
	EXPECT_EQ(finchfs_find("/find2", "name == \"*\"", &param,
			       &filler_find_called, filler_find),
		  0);
	EXPECT_EQ(filler_find_called, 10001);
	EXPECT_EQ(param.total_nentries, 10001);
	EXPECT_EQ(param.match_nentries, 10001);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, FIND3)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	EXPECT_EQ(finchfs_mkdir("/find3", S_IRWXU), 0);
	for (int i = 0; i < 100; i++) {
		char path[128];
		sprintf(path, "/find3/%d", i);
		int fd;
		fd = finchfs_create(path, O_RDWR, S_IRWXU);
		EXPECT_EQ(fd, 0);
		finchfs_close(fd);
	}
	finchfs_find_param param = {
	    .flag = FINCHFS_FIND_FLAG_RECURSIVE,
	};
	EXPECT_EQ(finchfs_find("/find3", "name == \"*5*\"", &param, NULL, NULL),
		  0);
	EXPECT_EQ(param.total_nentries, 101);
	EXPECT_EQ(param.match_nentries, 19);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, FIND4)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	EXPECT_EQ(finchfs_mkdir("/find4", S_IRWXU), 0);
	char buf[1024];
	rnd_fill(buf, sizeof(buf));
	for (int i = 0; i < 100; i++) {
		char path[128];
		sprintf(path, "/find4/%d", i);
		int fd;
		fd = finchfs_create(path, O_RDWR, S_IRWXU);
		EXPECT_EQ(fd, 0);
		EXPECT_EQ(finchfs_write(fd, buf, i + 1), i + 1);
		finchfs_close(fd);
	}
	finchfs_find_param param = {
	    .flag = FINCHFS_FIND_FLAG_RECURSIVE,
	};
	EXPECT_EQ(
	    finchfs_find("/find4", "size>=10 && size<20", &param, NULL, NULL),
	    0);
	EXPECT_EQ(param.total_nentries, 101);
	EXPECT_EQ(param.match_nentries, 10);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, FIND5)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	EXPECT_EQ(finchfs_mkdir("/find5", S_IRWXU), 0);
	char buf[1024];
	for (int i = 0; i < 100; i++) {
		sprintf(buf, "/find5/%d", i);
		EXPECT_EQ(finchfs_mkdir(buf, S_IRWXU), 0);
	}
	for (int i = 0; i < 10000; i++) {
		sprintf(buf, "/find5/%d/%d", i % 100, i);
		int fd;
		fd = finchfs_create(buf, O_RDWR, S_IRWXU);
		EXPECT_EQ(fd, 0);
		finchfs_close(fd);
	}
	finchfs_find_param param = {
	    .flag = FINCHFS_FIND_FLAG_RECURSIVE,
	};
	EXPECT_EQ(finchfs_find("/find5", "name == \"*\"", &param, NULL, NULL),
		  0);
	EXPECT_EQ(param.total_nentries, 10101);
	EXPECT_EQ(param.match_nentries, 10101);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, FIND6)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	EXPECT_EQ(finchfs_mkdir("/find6", S_IRWXU), 0);
	char buf[1024];
	for (int i = 0; i < 100; i++) {
		sprintf(buf, "/find6/%d", i);
		EXPECT_EQ(finchfs_mkdir(buf, S_IRWXU), 0);
	}
	for (int i = 0; i < 10000; i++) {
		sprintf(buf, "/find6/%d/%d", i % 100, i);
		int fd;
		fd = finchfs_create(buf, O_RDWR, S_IRWXU);
		EXPECT_EQ(fd, 0);
		finchfs_close(fd);
	}
	finchfs_find_param param = {
	    .flag = FINCHFS_FIND_FLAG_RECURSIVE,
	};
	EXPECT_EQ(finchfs_find("/find6", "name == \"*5*\"", &param, NULL, NULL),
		  0);
	EXPECT_EQ(param.total_nentries, 10101);
	EXPECT_EQ(param.match_nentries, 3458);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Sparse)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create_chunk_size("/sparse", O_RDWR, S_IRWXU, 1);
	EXPECT_EQ(fd, 0);
	char a = 'a';
	char c = 'c';
	char d = 'd';
	EXPECT_EQ(finchfs_pwrite(fd, &a, 1, 0), 1);
	EXPECT_EQ(finchfs_pwrite(fd, &c, 1, 2), 1);
	EXPECT_EQ(finchfs_pwrite(fd, &d, 1, 3), 1);
	char buf[4];
	EXPECT_EQ(finchfs_pread(fd, buf, 4, 0), 4);
	EXPECT_EQ(buf[0], 'a');
	EXPECT_EQ(buf[1], '\0');
	EXPECT_EQ(buf[2], 'c');
	EXPECT_EQ(buf[3], 'd');
	EXPECT_EQ(finchfs_close(fd), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Sparse2)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd1, fd2;
	fd1 = finchfs_create_chunk_size("/sparse2", O_RDWR, S_IRWXU, 1);
	EXPECT_EQ(fd1, 0);
	fd2 = finchfs_open("/sparse2", 0);
	EXPECT_EQ(fd2, 1);
	char a = 'a';
	char c = 'c';
	char d = 'd';
	EXPECT_EQ(finchfs_pwrite(fd1, &a, 1, 0), 1);
	EXPECT_EQ(finchfs_pwrite(fd1, &c, 1, 2), 1);
	EXPECT_EQ(finchfs_pwrite(fd1, &d, 1, 3), 1);
	char buf[4];
	EXPECT_EQ(finchfs_pread(fd2, buf, 4, 0), 4);
	EXPECT_EQ(buf[0], 'a');
	EXPECT_EQ(buf[1], '\0');
	EXPECT_EQ(buf[2], 'c');
	EXPECT_EQ(buf[3], 'd');
	EXPECT_EQ(finchfs_close(fd1), 0);
	EXPECT_EQ(finchfs_close(fd2), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Sparse3)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd1, fd2;
	fd1 = finchfs_create_chunk_size("/sparse3", O_RDWR, S_IRWXU, 1);
	EXPECT_EQ(fd1, 0);
	fd2 = finchfs_open("/sparse3", 0);
	EXPECT_EQ(fd2, 1);
	char a = 'a';
	char c = 'c';
	char d = 'd';
	EXPECT_EQ(finchfs_pwrite(fd1, &a, 1, 0), 1);
	EXPECT_EQ(finchfs_pwrite(fd1, &c, 1, 2), 1);
	EXPECT_EQ(finchfs_pwrite(fd1, &d, 1, 3), 1);
	char buf[4];
	EXPECT_EQ(finchfs_pread(fd2, buf, 2, 0), 1);
	EXPECT_EQ(buf[0], 'a');
	EXPECT_EQ(finchfs_close(fd1), 0);
	EXPECT_EQ(finchfs_close(fd2), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Sparse4)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create_chunk_size("/sparse4", O_RDWR, S_IRWXU, 2);
	EXPECT_EQ(fd, 0);
	char a = 'a';
	char c = 'c';
	char d = 'd';
	EXPECT_EQ(finchfs_pwrite(fd, &a, 1, 0), 1);
	EXPECT_EQ(finchfs_pwrite(fd, &c, 1, 2), 1);
	EXPECT_EQ(finchfs_pwrite(fd, &d, 1, 3), 1);
	char buf[4];
	EXPECT_EQ(finchfs_pread(fd, buf, 4, 0), 4);
	EXPECT_EQ(buf[0], 'a');
	EXPECT_EQ(buf[1], '\0');
	EXPECT_EQ(buf[2], 'c');
	EXPECT_EQ(buf[3], 'd');
	EXPECT_EQ(finchfs_close(fd), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Sparse5)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd1, fd2;
	fd1 = finchfs_create_chunk_size("/sparse5", O_RDWR, S_IRWXU, 2);
	EXPECT_EQ(fd1, 0);
	fd2 = finchfs_open("/sparse5", O_RDWR);
	EXPECT_EQ(fd2, 1);
	char a = 'a';
	char c = 'c';
	char d = 'd';
	EXPECT_EQ(finchfs_pwrite(fd1, &a, 1, 0), 1);
	EXPECT_EQ(finchfs_pwrite(fd1, &c, 1, 2), 1);
	EXPECT_EQ(finchfs_pwrite(fd1, &d, 1, 3), 1);
	char buf[4];
	EXPECT_EQ(finchfs_pread(fd2, buf, 4, 0), 4);
	EXPECT_EQ(buf[0], 'a');
	EXPECT_EQ(buf[1], '\0');
	EXPECT_EQ(buf[2], 'c');
	EXPECT_EQ(buf[3], 'd');
	EXPECT_EQ(finchfs_close(fd1), 0);
	EXPECT_EQ(finchfs_close(fd2), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Seek)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create("/seek", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	char buf[128];
	rnd_fill(buf, sizeof(buf));
	EXPECT_EQ(finchfs_write(fd, buf, sizeof(buf)), sizeof(buf));
	EXPECT_EQ(finchfs_seek(fd, 64, SEEK_SET), 64);
	char buf2[64];
	EXPECT_EQ(finchfs_read(fd, buf2, sizeof(buf2)), sizeof(buf2));
	EXPECT_TRUE(memcmp(buf + 64, buf2, sizeof(buf2)) == 0);
	EXPECT_EQ(finchfs_close(fd), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Seek2)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create("/seek2", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	char buf[128];
	rnd_fill(buf, sizeof(buf));
	EXPECT_EQ(finchfs_write(fd, buf, sizeof(buf)), sizeof(buf));
	EXPECT_EQ(finchfs_seek(fd, -64, SEEK_END), 64);
	char buf2[64];
	EXPECT_EQ(finchfs_read(fd, buf2, sizeof(buf2)), sizeof(buf2));
	EXPECT_TRUE(memcmp(buf + 64, buf2, sizeof(buf2)) == 0);
	EXPECT_EQ(finchfs_close(fd), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Seek3)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create("/seek3", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	char buf[128];
	rnd_fill(buf, sizeof(buf));
	EXPECT_EQ(finchfs_write(fd, buf, sizeof(buf)), sizeof(buf));
	EXPECT_EQ(finchfs_seek(fd, -64, SEEK_CUR), 64);
	char buf2[64];
	EXPECT_EQ(finchfs_read(fd, buf2, sizeof(buf2)), sizeof(buf2));
	EXPECT_TRUE(memcmp(buf + 64, buf2, sizeof(buf2)) == 0);
	EXPECT_EQ(finchfs_close(fd), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, CloseAfterUnlink)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create("/close_after_unlink", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	EXPECT_EQ(finchfs_unlink("/close_after_unlink"), 0);
	EXPECT_EQ(finchfs_close(fd), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Access_Perm_Read)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create("/perm1", O_WRONLY, S_IRWXU);
	EXPECT_EQ(fd, 0);
	char buf[1024];
	EXPECT_EQ(finchfs_read(fd, buf, 1024), -1);
	EXPECT_EQ(finchfs_close(fd), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Access_Perm_Write)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create("/perm2", O_RDONLY, S_IRWXU);
	EXPECT_EQ(fd, 0);
	char buf[1024];
	EXPECT_EQ(finchfs_write(fd, buf, 1024), -1);
	EXPECT_EQ(finchfs_close(fd), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Createat)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	EXPECT_EQ(finchfs_mkdir("/createat", 0777), 0);
	int dirfd, fd;
	dirfd = finchfs_open("/createat", O_RDWR | O_DIRECTORY);
	EXPECT_EQ(dirfd, 0);
	fd = finchfs_createat(dirfd, "file1", O_RDONLY, S_IRWXU);
	EXPECT_EQ(fd, 1);
	EXPECT_EQ(finchfs_close(fd), 0);
	EXPECT_EQ(finchfs_close(dirfd), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Openat)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int dirfd, fd;
	dirfd = finchfs_open("/createat", O_RDWR | O_DIRECTORY);
	EXPECT_EQ(dirfd, 0);
	fd = finchfs_openat(dirfd, "file1", O_RDWR);
	EXPECT_EQ(fd, 1);
	char buf[1024];
	EXPECT_EQ(finchfs_write(fd, buf, 1024), 1024);
	EXPECT_EQ(finchfs_close(fd), 0);
	EXPECT_EQ(finchfs_close(dirfd), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Fstatat)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int dirfd;
	dirfd = finchfs_open("/createat", O_RDWR | O_DIRECTORY);
	EXPECT_EQ(dirfd, 0);
	struct stat st;
	EXPECT_EQ(finchfs_fstatat(dirfd, "file1", &st, 0), 0);
	EXPECT_EQ(st.st_size, 1024);
	EXPECT_EQ(finchfs_close(dirfd), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Fstatat2)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int dirfd;
	dirfd = finchfs_open("/createat", O_RDWR | O_DIRECTORY);
	EXPECT_EQ(dirfd, 0);
	struct stat st;
	EXPECT_EQ(finchfs_fstatat(dirfd, "", &st, AT_EMPTY_PATH), 0);
	EXPECT_EQ(finchfs_close(dirfd), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

struct test_dirent {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    char pad;
    char           d_name[];
};

TEST(FinchfsTest, Getdents)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int dirfd;
	dirfd = finchfs_open("/createat", O_RDWR | O_DIRECTORY);
	EXPECT_EQ(dirfd, 0);
	char buf[2048];
	EXPECT_EQ(finchfs_getdents(dirfd, buf, 2048), 30);
	struct test_dirent *ent = (struct test_dirent *)buf;
	EXPECT_STREQ(ent->d_name, "file1");
	EXPECT_EQ(finchfs_close(dirfd), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Mkdirat)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int dirfd;
	dirfd = finchfs_open("/createat", O_RDWR | O_DIRECTORY);
	EXPECT_EQ(dirfd, 0);
	EXPECT_EQ(finchfs_mkdirat(dirfd, "mkdirat", 0777), 0);
	EXPECT_EQ(finchfs_close(dirfd), 0);
	struct stat st;
	EXPECT_EQ(finchfs_stat("/createat/mkdirat", &st), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Unlinkat1)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int dirfd;
	dirfd = finchfs_open("/createat", O_RDWR | O_DIRECTORY);
	EXPECT_EQ(dirfd, 0);
	EXPECT_EQ(finchfs_unlinkat(dirfd, "file1", 0), 0);
	EXPECT_EQ(finchfs_close(dirfd), 0);
	struct stat st;
	EXPECT_EQ(finchfs_stat("/createat/file1", &st), -1);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Unlinkat2)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int dirfd;
	dirfd = finchfs_open("/createat", O_RDWR | O_DIRECTORY);
	EXPECT_EQ(dirfd, 0);
	EXPECT_EQ(finchfs_unlinkat(dirfd, "mkdirat", AT_REMOVEDIR), 0);
	EXPECT_EQ(finchfs_close(dirfd), 0);
	struct stat st;
	EXPECT_EQ(finchfs_stat("/createat/mkdirat", &st), -1);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Renameat1)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	EXPECT_EQ(finchfs_mkdir("/renameat", 0777), 0);
	EXPECT_EQ(finchfs_mkdir("/renameat/childdir", 0777), 0);
	int dirfd;
	dirfd = finchfs_open("/renameat", O_RDWR | O_DIRECTORY);
	EXPECT_EQ(dirfd, 0);
	EXPECT_EQ(finchfs_renameat(dirfd, "childdir", dirfd, "childdir2"), 0);
	EXPECT_EQ(finchfs_close(dirfd), 0);
	struct stat st;
	EXPECT_EQ(finchfs_stat("/renameat/childdir", &st), -1);
	EXPECT_EQ(finchfs_stat("/renameat/childdir2", &st), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Renameat2)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create("/renameat/childfile", O_RDONLY, S_IRWXU);
	EXPECT_EQ(fd, 0);
	EXPECT_EQ(finchfs_close(fd), 0);
	int dirfd;
	dirfd = finchfs_open("/renameat", O_RDWR | O_DIRECTORY);
	EXPECT_EQ(dirfd, 0);
	EXPECT_EQ(finchfs_renameat(dirfd, "childfile", dirfd, "childfile2"), 0);
	EXPECT_EQ(finchfs_close(dirfd), 0);
	struct stat st;
	EXPECT_EQ(finchfs_stat("/renameat/childfile", &st), -1);
	EXPECT_EQ(finchfs_stat("/renameat/childfile2", &st), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Mmap1)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	int fd;
	fd = finchfs_create("/mmap1", O_RDWR, S_IRWXU);
	EXPECT_EQ(fd, 0);
	char *text = "ABCDEFGH";
	EXPECT_EQ(finchfs_write(fd, text, strlen(text) + 1), strlen(text) + 1);
	char *addr;
	addr = (char *)finchfs_mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	EXPECT_NE(addr, MAP_FAILED);
	EXPECT_STREQ(addr, text);
	EXPECT_EQ(finchfs_close(fd), 0);
	EXPECT_EQ(finchfs_munmap(addr, 4096), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

TEST(FinchfsTest, Root)
{
	EXPECT_EQ(finchfs_init(NULL), 0);
	struct stat st;
	EXPECT_EQ(finchfs_stat("/", &st), 0);
	EXPECT_EQ(finchfs_term(), 0);
}

static int
path_to_target_hash(const char *path, int div)
{
	long h = 0;
	int slash = -1;
	char *head = strdup(path);
	char *next;
	long n;
	for (int i = 0; head[i] != '\0'; i++) {
		if (head[i] == '/') {
			slash = i;
		}
	}
	for (char *p = head + slash + 1; *p != '\0'; p = next) {
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
	EXPECT_EQ(path_to_target_hash("foo1", 8), 5);
	EXPECT_EQ(path_to_target_hash("foo2", 8), 6);
	EXPECT_EQ(path_to_target_hash("foo3", 8), 7);
	EXPECT_EQ(path_to_target_hash("foo4", 8), 0);
	EXPECT_EQ(path_to_target_hash("foo5", 8), 1);
	EXPECT_EQ(path_to_target_hash("foo6", 8), 2);
	EXPECT_EQ(path_to_target_hash("foo7", 8), 3);
	EXPECT_EQ(path_to_target_hash("foo8", 8), 4);
	EXPECT_EQ(path_to_target_hash("foo9", 8), 5);
	EXPECT_EQ(path_to_target_hash("foo10", 8), 6);
}

TEST(HashTest, Hash2)
{
	EXPECT_EQ(path_to_target_hash("foo01", 8), 5);
	EXPECT_EQ(path_to_target_hash("foo02", 8), 6);
	EXPECT_EQ(path_to_target_hash("foo03", 8), 7);
	EXPECT_EQ(path_to_target_hash("foo04", 8), 0);
	EXPECT_EQ(path_to_target_hash("foo05", 8), 1);
	EXPECT_EQ(path_to_target_hash("foo06", 8), 2);
	EXPECT_EQ(path_to_target_hash("foo07", 8), 3);
	EXPECT_EQ(path_to_target_hash("foo08", 8), 4);
	EXPECT_EQ(path_to_target_hash("foo09", 8), 5);
	EXPECT_EQ(path_to_target_hash("foo10", 8), 6);
}

TEST(HashTest, Hash3)
{
	EXPECT_EQ(path_to_target_hash("bar/foo01", 8), 5);
	EXPECT_EQ(path_to_target_hash("bar/foo02", 8), 6);
	EXPECT_EQ(path_to_target_hash("bar/foo03", 8), 7);
	EXPECT_EQ(path_to_target_hash("bar/foo04", 8), 0);
	EXPECT_EQ(path_to_target_hash("bar/foo05", 8), 1);
	EXPECT_EQ(path_to_target_hash("bar/foo06", 8), 2);
	EXPECT_EQ(path_to_target_hash("bar/foo07", 8), 3);
	EXPECT_EQ(path_to_target_hash("bar/foo08", 8), 4);
	EXPECT_EQ(path_to_target_hash("bar/foo09", 8), 5);
	EXPECT_EQ(path_to_target_hash("bar/foo10", 8), 6);
}

static void
get_parent_and_filename(char *filename, const char *path)
{
	char *prev = (char *)path;
	char *p = prev;
	int path_len = strlen(path) + 1;
	char name[128];
	while ((p = strchr(p, '/')) != NULL) {
		memcpy(name, prev, p - prev);
		name[p - prev] = '\0';
		prev = ++p;
	}
	memcpy(filename, prev, path_len - (prev - path));
	filename[path_len - (prev - path)] = '\0';
}

TEST(HashTest, DIG_DIR)
{
	char filename[128];
	get_parent_and_filename(filename, "foo/bar/baz");
	EXPECT_STREQ(filename, "baz");
	get_parent_and_filename(filename, "foo");
	EXPECT_STREQ(filename, "foo");
}

int
main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
