void fs_inode_init(char *db_dir);
int fs_inode_create(char *path, mode_t mode, size_t chunk_size, uint32_t i_ino);
int fs_inode_unlink(char *path, uint32_t *i_ino);
int fs_inode_stat(char *path, fs_stat_t *st);
ssize_t fs_inode_write(uint32_t i_ino, uint32_t index, off_t offset,
		       size_t size, const void *buf);
ssize_t fs_inode_read(uint32_t i_ino, uint32_t index, off_t offset, size_t size,
		      void *buf);
