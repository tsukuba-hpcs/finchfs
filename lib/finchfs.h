int finchfs_init(const char *addrfile);
int finchfs_term();
int finchfs_open(const char *path, int32_t flags);
int finchfs_close(int fd);
int finchfs_mkdir(const char *path, mode_t mode);
int finchfs_rmdir(const char *path);
