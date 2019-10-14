#include <ngx_module.h>
#include <ngx_string.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_lua_common.h"
#include "ngx_http_lua_shdict.h"

typedef struct {
    ngx_rbtree_t                  rbtree;
    ngx_rbtree_node_t             sentinel;
    ngx_queue_t                   lru_queue;
} ngx_http_lua_ipc_shctx_t;

typedef struct {
    ngx_array_t         *shdict_zones;
    unsigned             requires_shm:1;
} ngx_http_lua_ipc_conf_t;

typedef struct {
    ngx_http_lua_ipc_shctx_t     *sh;
    ngx_slab_pool_t              *shpool;
    ngx_str_t                     name;
	ngx_http_lua_ipc_conf_t      *conf;
    ngx_log_t                    *log;
} ngx_http_lua_ipc_ctx_t;

typedef struct {
	uint64_t                      curr_idx;
} ngx_http_lua_ipc_subscriber_t;


// node stored in linked_list
typedef struct ngx_http_lua_ipc_list_node_t {
	struct ngx_http_lua_ipc_list_node_t  *next;
	struct ngx_http_lua_ipc_list_node_t  *prev;
	size_t                                size;
	uint8_t	                              ref_count;
	void                                 *data;
} ngx_http_lua_ipc_list_node_t;

// node stored in rbtree
typedef struct ngx_http_lua_ipc_channel_s ngx_http_lua_ipc_channel_t;

struct ngx_http_lua_ipc_channel_s {
	u_char                               *name;     /* channel name */
	ngx_uint_t                            name_len;
	ngx_uint_t                            size;     /* linked list length */
	ngx_http_lua_ipc_list_node_t         *head;     /* linked list head */
	ngx_http_lua_ipc_subscriber_t        *subscribers;
	ngx_http_lua_ipc_list_node_t        **nodes;
};


static char* ngx_http_lua_ipc(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

ngx_int_t ngx_http_lua_ipc_init(ngx_shm_zone_t *shm_zone, void *data);

void ngx_http_lua_ipc_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

static void* ngx_http_ipc_create_main_conf(ngx_conf_t *cf);
extern int ngx_http_lua_ipc_new(u_char* shm_name, u_char *chname, size_t size, ngx_http_lua_ipc_channel_t **out);

extern int ngx_http_lua_ffi_ipc_channel_free(ngx_http_lua_ipc_channel_t **channel);

