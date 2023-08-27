#define RPC_MKDIR_REQ 0x01

int fs_rpc_mkdir(const char *path, mode_t mode);

int fs_client_init(char *addrfile);
int fs_client_term(void);

int fs_server_init(ucp_worker_h worker);
