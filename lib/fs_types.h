typedef struct {
	size_t chunk_size;
	uint32_t i_ino;
	uint32_t mode;
	struct timespec mtime, ctime;
} fs_stat_t;

typedef struct {
	void *handle;
	uint32_t i_ino;
	uint32_t index;
	off_t offset;
} inode_write_header_t;

typedef struct {
	void *handle;
	uint32_t i_ino;
	uint32_t index;
	off_t offset;
	ssize_t size;
	int ret;
} inode_read_header_t;

typedef enum {
	FINCH_OK = 0,
	FINCH_INPROGRESS = 1,
	FINCH_ENOENT = -2,
	FINCH_EIO = -5,
	FINCH_EEXIST = -17,
} finch_status_t;
