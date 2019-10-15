#ifndef _NGX_HTTP_LUA_FFI_IPC_H_
#define _NGX_HTTP_LUA_FFI_IPC_H_

#include <ngx_module.h>
#include <ngx_string.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_lua_common.h"
#include "ngx_http_lua_shdict.h"

#define BIT(X) 0x0001 << X

#define NGX_HTTP_LUA_FFI_IPC_SAFE    BIT(0)
#define NGX_HTTP_LUA_FFI_IPC_DESTROY BIT(1)

typedef struct {
    ngx_rbtree_t                  rbtree;
    ngx_rbtree_node_t             sentinel;
    ngx_queue_t                   lru_queue;
} ngx_http_lua_ipc_shctx_t;

typedef struct {
    ngx_array_t                  *shdict_zones;
    unsigned                      requires_shm:1;
} ngx_http_lua_ipc_conf_t;

typedef struct {
    ngx_http_lua_ipc_shctx_t     *sh;
    ngx_slab_pool_t              *shpool;
    ngx_str_t                     name;
	ngx_http_lua_ipc_conf_t      *conf;
    ngx_log_t                    *log;
} ngx_http_lua_ipc_ctx_t;

// node stored in linked_list
typedef struct ngx_http_lua_ipc_list_node_t {
	struct ngx_http_lua_ipc_list_node_t  *next;
	struct ngx_http_lua_ipc_list_node_t  *prev;
	size_t                                size;
	uint8_t	                              refs;
	uint64_t                              idx; // overflow not handled
	void                                 *data;
} ngx_http_lua_ipc_list_node_t;

typedef struct ngx_http_lua_ipc_subscriber_s ngx_http_lua_ipc_subscriber_t;

struct ngx_http_lua_ipc_subscriber_s {
	uint64_t                              idx;
	ngx_http_lua_ipc_list_node_t         *node;
	struct ngx_http_lua_ipc_subscriber_s *next;
};


// node stored in rbtree
typedef struct ngx_http_lua_ffi_ipc_channel_s ngx_http_lua_ffi_ipc_channel_t;

struct ngx_http_lua_ffi_ipc_channel_s {
	ngx_str_t                             name;
	ngx_uint_t                            size;     /* linked list length */
	ngx_uint_t                            refs;
	uint16_t                              flags;    /* destroy;safe; */
	ngx_shm_zone_t                       *zone;
	ngx_http_lua_ipc_list_node_t         *head;     /* linked list head */
	ngx_http_lua_ipc_subscriber_t       **subscribers;
	ngx_http_lua_ipc_list_node_t         *nodes;
	//chname
	//nodes...
};


extern int ngx_http_lua_ffi_ipc_new(const char* shm_name, const char *chname,
	size_t size, uint8_t safe, uint8_t destroy,
	ngx_http_lua_ffi_ipc_channel_t **out);
extern void ngx_http_lua_ffi_ipc_free_channel(
	ngx_http_lua_ffi_ipc_channel_t **channel);
extern int ngx_http_lua_ffi_ipc_channel_subscribe(
	ngx_http_lua_ffi_ipc_channel_t *channel, uint8_t start);

extern int ngx_http_lua_ffi_ipc_free_subscriber(
	ngx_http_lua_ipc_subscriber_t **subcriber);

void ngx_http_lua_ipc_rbtree_insert_value(ngx_rbtree_node_t *temp,
       ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
#endif /* _NGX_HTTP_LUA_FFI_IPC_H_ */
