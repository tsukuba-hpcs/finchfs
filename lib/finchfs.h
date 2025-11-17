int finchfs_init(const char *addrfile);
int finchfs_term();
const char *finchfs_version();
void finchfs_set_chunk_size(size_t chunk_size);
int finchfs_create(const char *path, int32_t flags, mode_t mode);
int finchfs_create_chunk_size(const char *path, int32_t flags, mode_t mode,
			      size_t chunk_size);
int finchfs_open(const char *path, int32_t flags);
int finchfs_close(int fd);
ssize_t finchfs_pwrite(int fd, const void *buf, size_t size, off_t offset);
ssize_t finchfs_write(int fd, const void *buf, size_t size);
ssize_t finchfs_pread(int fd, void *buf, size_t size, off_t offset);
ssize_t finchfs_read(int fd, void *buf, size_t size);
off_t finchfs_seek(int fd, off_t offset, int whence);
int finchfs_fsync(int fd);
int finchfs_unlink(const char *path);
int finchfs_mkdir(const char *path, mode_t mode);
int finchfs_rmdir(const char *path);
int finchfs_stat(const char *path, struct stat *st);
int finchfs_fstat(int fd, struct stat *st);
int finchfs_rename(const char *oldpath, const char *newpath);
int finchfs_link(const char *oldpath, const char *newpath);
int finchfs_createat(int dirfd, const char *pathname, int flags, mode_t mode);
int finchfs_createat_chunk_size(int dirfd, const char *pathname, int flags,
				mode_t mode, size_t chunk_size);
int finchfs_openat(int dirfd, const char *pathname, int flags);
int finchfs_fstatat(int dirfd, const char *pathname, struct stat *buf,
		    int flags);
int finchfs_mkdirat(int dirfd, const char *pathname, mode_t mode);
int finchfs_unlinkat(int dirfd, const char *pathname, int flags);
int finchfs_renameat(int olddirfd, const char *oldpath, int newdirfd,
		     const char *newpath);
int finchfs_linkat(int olddirfd, const char *oldpath, int newdirfd,
		   const char *newpath);
ssize_t finchfs_getdents(int fd, void *dirp, size_t count);
void *finchfs_mmap(void *addr, size_t length, int prot, int flags, int fd,
		   off_t offset);
int finchfs_munmap(void *addr, size_t length);
