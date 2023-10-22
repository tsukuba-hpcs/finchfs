===========
FINCHFS API
===========

.. code-block:: c

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
    int finchfs_readdir(const char *path, void *buf,
		    void (*filler)(void *, const char *, const struct stat *));
    int finchfs_rename(const char *oldpath, const char *newpath);
    typedef enum {
        FINCHFS_FIND_FLAG_RECURSIVE = (1 << 0),
        FINCHFS_FIND_FLAG_RETURN_PATH = (1 << 1),
    } finchfs_find_flag_t;
    struct finchfs_find_param {
        uint8_t flag;
        size_t total_nentries;
        size_t match_nentries;
    };
    int finchfs_find(const char *path, const char *query,
        struct finchfs_find_param *param, void *buf,
        void (*filler)(void *, const char *));
