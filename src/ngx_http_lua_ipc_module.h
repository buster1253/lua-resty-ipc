#ifndef _NGX_HTTP_LUA_IPC_H_
#define _NGX_HTTP_LUA_IPC_H_

#include <ngx_module.h>
#include <ngx_string.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_lua_common.h"
#include "ngx_http_lua_shdict.h"

#define BIT(X) 0x0001 << X

#define NGX_HTTP_LUA_IPC_SAFE     BIT(0)
#define NGX_HTTP_LUA_IPC_DESTROY  BIT(1)
#define NGX_HTTP_LUA_IPC_MAX_SIZE 1024


//testing
#define NGX_HTTP_LUA_IPC_DEFAULT_SIZE 256

typedef struct ngx_http_lua_ipc_subscriber_s ngx_http_lua_ipc_subscriber_t;
typedef struct ngx_http_lua_ipc_channel_s    ngx_http_lua_ipc_channel_t;
typedef struct ngx_http_lua_ipc_list_node_s  ngx_http_lua_ipc_list_node_t;
typedef struct ngx_http_lua_ipc_msg_s        ngx_http_lua_ipc_msg_t;

typedef struct {
    ngx_rbtree_t                          rbtree;
    ngx_rbtree_node_t                     sentinel;
    ngx_queue_t                           lru_queue;
} ngx_http_lua_ipc_shctx_t;

typedef struct {
    ngx_array_t                          *shdict_zones;
    unsigned                              requires_shm:1;
} ngx_http_lua_ipc_conf_t;

typedef struct {
    ngx_http_lua_ipc_shctx_t             *sh;
    ngx_slab_pool_t                      *shpool;
    ngx_str_t                             name;
    ngx_http_lua_ipc_conf_t              *conf;
    ngx_log_t                            *log;
} ngx_http_lua_ipc_ctx_t;


struct ngx_http_lua_ipc_msg_s {
    uint8_t                               refs;
    uint32_t                              size;
    uint32_t                              memsize;
    uint32_t                              idx;
    uint32_t                              unread;
    unsigned char                         type[20];
    unsigned char                        *data;
};

struct ngx_http_lua_ipc_list_node_s {
    struct ngx_http_lua_ipc_list_node_s  *next;
    struct ngx_http_lua_ipc_list_node_s  *prev;
    ngx_http_lua_ipc_msg_t                msg;
};

struct ngx_http_lua_ipc_channel_s {
    ngx_str_t                             name;
    ngx_rbtree_node_t                    *channel_node;
    ngx_uint_t                            size;     /* linked list length */
    ngx_uint_t                            refs;
    uint16_t                              flags;    /* destroy;safe; */
    uint32_t                              counter;
    uint32_t                              subscribers;
    uint32_t                              def_msg_size;
    ngx_shm_zone_t                       *zone;
    ngx_http_lua_ipc_list_node_t         *head;     /* linked list head */
    ngx_http_lua_ipc_list_node_t          nodes[0];
};

struct ngx_http_lua_ipc_subscriber_s {
    uint64_t                              idx;
    ngx_http_lua_ipc_list_node_t         *node;
    ngx_http_lua_ipc_channel_t           *channel;
    uint32_t                              skipped;
    ngx_http_lua_ipc_msg_t               *msg;
};

int ngx_http_lua_ffi_ipc_new(const char* shm_name, const char *chname,
    size_t size, uint8_t safe, uint8_t destroy,
    ngx_http_lua_ipc_channel_t **out);

void ngx_http_lua_ffi_ipc_free_channel(
    ngx_http_lua_ipc_channel_t **channel);

int ngx_http_lua_ffi_ipc_channel_subscribe(
    ngx_http_lua_ipc_channel_t *channel, int start,
    ngx_http_lua_ipc_subscriber_t **out);

void ngx_http_lua_ffi_ipc_free_subscriber(
    ngx_http_lua_ipc_subscriber_t **subcriber);

int ngx_http_lua_ffi_ipc_get_message(
    ngx_http_lua_ipc_subscriber_t *subscriber);

void ngx_http_lua_ffi_ipc_ack_msg(ngx_http_lua_ipc_subscriber_t *sub);

#endif /* _NGX_HTTP_LUA_IPC_H_ */
