#define RPC_MKDIR_REQ 0x01
#define RPC_MKDIR_REP 0x02

int fs_rpc_mkdir(const char *path, mode_t mode);

int fs_client_init(char *addrfile);
int fs_client_term(void);

int fs_server_init(ucp_worker_h worker);
int fs_server_term();

typedef enum {
	FINCH_OK = 0,
	FINCH_INPROGRESS = 1,
	FINCH_EEXIST = -17,
} finch_status_t;

typedef struct {
	void *header;
	int n;
	ucp_dt_iov_t iov[];
} iov_req_t;