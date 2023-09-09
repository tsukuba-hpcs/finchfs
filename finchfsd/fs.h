void fs_inode_init(char *db_dir);
ssize_t fs_inode_write(uint64_t i_ino, uint64_t index, off_t offset,
		       size_t size, const void *buf);
ssize_t fs_inode_read(uint64_t i_ino, uint64_t index, off_t offset, size_t size,
		      void *buf);
int fs_inode_truncate(uint64_t i_ino, uint64_t index, off_t offset);
