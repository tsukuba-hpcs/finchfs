void fs_inode_init(char *db_dir);
int fs_inode_create(char *path, mode_t mode, size_t chunk_size, uint32_t i_ino);
int fs_inode_stat(char *path, fs_stat_t *st);
