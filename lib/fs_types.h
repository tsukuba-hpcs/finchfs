typedef struct {
	size_t chunk_size;
	uint64_t i_ino;
	uint64_t mode;
	struct timespec mtime, ctime;
	size_t size;
} fs_stat_t;

typedef struct {
	void *handle;
	uint64_t i_ino;
	uint64_t index;
	off_t offset;
} inode_write_header_t;

typedef struct {
	void *handle;
	uint64_t i_ino;
	uint64_t index;
	off_t offset;
	ssize_t size;
	int ret;
} inode_read_header_t;

typedef struct {
	void *handle;
	size_t entry_count;
	int fileonly;
	int ret;
} readdir_header_t;

typedef struct {
	size_t chunk_size;
	uint64_t i_ino;
	uint64_t mode;
	struct timespec mtime, ctime;
	size_t size;
	int path_len;
	char path[];
} readdir_entry_t;

/* Number of 512B blocks */
#define NUM_BLOCKS(size) ((size + 511) / 512)

typedef enum {
	FINCH_OK = 0,
	FINCH_INPROGRESS = 1,
	FINCH_ENOENT = -2,
	FINCH_EIO = -5,
	FINCH_EEXIST = -17,
	FINCH_ENOTDIR = -20,
} finch_status_t;
