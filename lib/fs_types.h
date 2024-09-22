typedef struct {
	size_t chunk_size;
	uint64_t i_ino;
	uint64_t eid;
	mode_t mode;
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
	mode_t mode;
	struct timespec mtime, ctime;
	size_t size;
	int path_len;
	char path[];
} readdir_entry_t;

typedef struct {
	void *handle;
	size_t entry_count;
	int ret;
	size_t total_nentries;
	size_t match_nentries;
} find_header_t;

typedef struct {
	int path_len;
	char path[];
} find_entry_t;

typedef struct {
	void *handle;
	uint64_t pos;
	size_t count;
	int ret;
} getdents_header_t;

/* Number of 512B blocks */
#define NUM_BLOCKS(size) ((size + 511) / 512)

typedef enum {
	FINCH_OK = 0,
	FINCH_INPROGRESS = 1,
	FINCH_ENOENT = -2,
	FINCH_EIO = -5,
	FINCH_EEXIST = -17,
	FINCH_ENOTDIR = -20,
	FINCH_EINVAL = -22,
} finch_status_t;
