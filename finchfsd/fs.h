struct fs_ctx;

struct fs_ctx *fs_inode_init(char *db_dir);
void fs_inode_term(struct fs_ctx *ctx);
ssize_t fs_inode_write(struct fs_ctx *ctx, uint64_t i_ino, uint64_t index,
		       off_t offset, size_t size, const void *buf);
ssize_t fs_inode_read(struct fs_ctx *ctx, uint64_t i_ino, uint64_t index,
		      off_t offset, size_t size, void *buf);
