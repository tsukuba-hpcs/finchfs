void fs_inode_init(char *db_dir);
ssize_t fs_inode_write(uint32_t i_ino, uint32_t index, off_t offset,
		       size_t size, const void *buf);
ssize_t fs_inode_read(uint32_t i_ino, uint32_t index, off_t offset, size_t size,
		      void *buf);
int fs_inode_chunk_stat(uint32_t i_ino, uint32_t index, size_t *size);
int fs_inode_truncate(uint32_t i_ino, uint32_t index, off_t offset);
