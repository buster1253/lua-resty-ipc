#include "ngx_http_lua_ipc_module.h"

static char* ngx_http_lua_ipc(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_lua_ipc_init(ngx_shm_zone_t *shm_zone, void *data);
static void* ngx_http_ipc_create_main_conf(ngx_conf_t *cf);
static void ngx_http_lua_ipc_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static void ngx_http_lua_ipc_decrement_channel_refs(
    ngx_http_lua_ipc_channel_t *channel, ngx_http_lua_ipc_ctx_t *ctx);
static ngx_shm_zone_t* ngx_http_lua_ffi_ipc_get_zone(const char *name,
    ngx_uint_t len);
static ngx_int_t ngx_http_lua_ipc_channel_lookup(ngx_shm_zone_t *zone,
    ngx_uint_t hash, const char *kdata, size_t klen,
    ngx_http_lua_ipc_channel_t **sdp);


static ngx_command_t ngx_http_lua_ipc_cmds[] = {
     { ngx_string("lua_ipc"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_lua_ipc,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL},

     ngx_null_command
};

static ngx_http_module_t  ngx_http_lua_ipc_module_ctx = {

    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    ngx_http_ipc_create_main_conf,  /* create main configuration */
    NULL,
    /*ngx_http_live_init_main_conf,   [> init main configuration <]*/

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,
    NULL,
    /*ngx_http_live_create_loc_conf,  [> create location configuration <]*/
    /*ngx_http_live_merge_loc_conf  [> merge location configuration <]*/
};

ngx_module_t ngx_http_lua_ipc_module = {
    NGX_MODULE_V1,
    &ngx_http_lua_ipc_module_ctx,     /* module context */
    ngx_http_lua_ipc_cmds,       /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                          /* init master */
    NULL,
    NULL,
    /*ngx_http_live_init_module,      [> init module <]*/
    /*ngx_http_live_init_process,    [> init process <]*/
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_ipc_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_lua_ipc_conf_t  *lmcf;

    lmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_lua_ipc_conf_t));
    if (lmcf == NULL) {
        return NULL;
    }

    return lmcf;
}

static char *
ngx_http_lua_ipc(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_lua_ipc_conf_t *lmcf = conf;
    ngx_str_t                 *value, name;
    ngx_shm_zone_t           *zone;
    ngx_shm_zone_t          **zp;
    ngx_http_lua_ipc_ctx_t   *ctx;
    size_t                   size;

    if (lmcf->shdict_zones == NULL) {
        lmcf->shdict_zones = ngx_palloc(cf->pool, sizeof(ngx_array_t));

        if (lmcf->shdict_zones == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_array_init(lmcf->shdict_zones, cf->pool, 2,
                           sizeof(ngx_shm_zone_t *))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    ctx = NULL;

    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid lua shared dict name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    name = value[1];

    size = ngx_parse_size(&value[2]);

    if (size <= 8191) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid lua shared dict size \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_lua_ipc_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->name = name;
    ctx->conf = lmcf;
    ctx->log = &cf->cycle->new_log;

    zone = ngx_shared_memory_add(cf, &name, (size_t) size,
                                &ngx_http_lua_ipc_module);
    if (zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (zone->data) {
        ctx = zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "lua_shared_dict \"%V\" is already defined as "
                           "\"%V\"", &name, &ctx->name);
        return NGX_CONF_ERROR;
    }

    /*zone->init = ngx_http_lua_shdict_init_zone;*/
    zone->init = ngx_http_lua_ipc_init;
    zone->data = ctx;

    zp = ngx_array_push(lmcf->shdict_zones);
    if (zp == NULL) {
        return NGX_CONF_ERROR;
    }

    *zp = zone;

    /*lmcf->requires_shm = 1;*/

    return NGX_CONF_OK;
}

ngx_int_t
ngx_http_lua_ipc_init(ngx_shm_zone_t *shm_zone, void *data) {

    size_t                 len;
    ngx_http_lua_ipc_ctx_t  *ctx;
    ngx_http_lua_ipc_ctx_t  *octx = data;

    ctx = shm_zone->data;

    if(octx) {
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_lua_ipc_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_lua_ipc_rbtree_insert_value);

    ngx_queue_init(&ctx->sh->lru_queue);

    len = sizeof(" in lua_shared_dict zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    /*ngx_uint_t r = ngx_shmtx_trylock(&ctx->shpool->mutex);*/
    /*ngx_sprintf(ctx->shpool->log_ctx, "trylock: &d", r);*/

    ngx_sprintf(ctx->shpool->log_ctx, " in lua_shared_dict zone \"%V\"%Z",
                &shm_zone->shm.name);

#if defined(nginx_version) && nginx_version >= 1005013
    ctx->shpool->log_nomem = 0;
#endif

    return NGX_OK;
}

static ngx_int_t
ngx_http_lua_ipc_channel_lookup(ngx_shm_zone_t *zone, ngx_uint_t hash,
        const char *kdata, size_t klen, ngx_http_lua_ipc_channel_t **sdp)
{
    ngx_http_lua_ipc_ctx_t  *ctx;
    ngx_rbtree_node_t      *node, *sentinel;
    ngx_http_lua_ipc_channel_t *sd;
    ngx_int_t                  rc;

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "channel lookup");

    ctx = zone->data;

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        sd = (ngx_http_lua_ipc_channel_t *) &node->data;

        rc = ngx_memn2cmp((u_char *)kdata, sd->name.data, klen, sd->name.len);

        if (rc == 0) {
            *sdp = sd;

            return NGX_OK;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    *sdp = NULL;

    return NGX_DECLINED;
}

static ngx_shm_zone_t *
ngx_http_lua_ffi_ipc_get_zone(const char *name, ngx_uint_t len)
{
    ngx_http_lua_ipc_conf_t *lmcf;
    ngx_shm_zone_t           *p;

    lmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_http_lua_ipc_module);
    if (!lmcf) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "Failed to get module config");
        return NULL;
    }

    p = *(ngx_shm_zone_t**)lmcf->shdict_zones->elts;

    for (ngx_uint_t i=0; i < lmcf->shdict_zones->nelts; i++) {
        if (len == p->shm.name.len &&
            ngx_strncmp(name, p->shm.name.data, len) == 0)
        {
            return p;
        }

        p += lmcf->shdict_zones->size;
    }

    return NULL;
}

/*safe:   try to guarantee message delivery
*destroy: free the channel when all refs are gone */

int
ngx_http_lua_ffi_ipc_new(const char *shm_name, const char *chname, size_t size,
    uint8_t safe, uint8_t destroy, ngx_http_lua_ipc_channel_t **out)
{

    ngx_shm_zone_t               *zone;
    ngx_rbtree_node_t             *channel_node;
    ngx_http_lua_ipc_channel_t   *channel;
    ngx_http_lua_ipc_list_node_t   *np;
    uint32_t                        hash;
    ngx_int_t                      rc;
    size_t                        n;

    ngx_uint_t shm_nlen = strlen(shm_name);
    ngx_uint_t chlen = strlen(chname);

    zone = ngx_http_lua_ffi_ipc_get_zone(shm_name, shm_nlen);

    if (zone == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "Could not find shared zone: %s", shm_name);
        return NGX_ERROR;
    }

    ngx_http_lua_ipc_ctx_t *ctx = (ngx_http_lua_ipc_ctx_t *) zone->data;
    ngx_shmtx_lock(&ctx->shpool->mutex);

    ngx_crc32_init(hash);
    ngx_crc32_update(&hash, (u_char*) chname, chlen);
    ngx_crc32_final(hash);

    rc = ngx_http_lua_ipc_channel_lookup(zone, hash, chname, chlen, &channel);

    if(rc == NGX_OK) {
        channel->refs++;
        *out = channel;

        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "Channel doesn't exist");


    n = offsetof(ngx_rbtree_node_t, data)
        + sizeof(ngx_http_lua_ipc_channel_t)
        + chlen
        + size * sizeof(ngx_http_lua_ipc_list_node_t);

    channel_node = ngx_slab_alloc_locked(ctx->shpool, n);

    if (channel_node == NULL) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "Failed to create channel: no memory");
        return NGX_DECLINED;
    }

    channel_node->key = hash;

    channel = (ngx_http_lua_ipc_channel_t *) &channel_node->data;
    channel->channel_node = channel_node;
    channel->size = size;
    channel->zone = zone;
    channel->counter = 0;
    channel->subscribers = 0;
    channel->name.len = chlen;
    channel->name.data = (u_char *) &channel->nodes
                         + size * sizeof(ngx_http_lua_ipc_list_node_t);

    /* TODO programmable */
    channel->def_msg_size = NGX_HTTP_LUA_IPC_DEFAULT_SIZE;

    ngx_memcpy(channel->name.data, chname, chlen);

    if (safe == 1) {
        channel->flags |= NGX_HTTP_LUA_IPC_SAFE;
    }
    if (destroy == 1) {
        channel->flags |= NGX_HTTP_LUA_IPC_DESTROY;
    }

    np = channel->nodes;
    channel->head = np;

    for (size_t i = 0; i < size; i++) {
        if (i == 0) {
            np->next = np + 1;
            np->prev = np + (size - 1);
        }
        else if (i == size - 1) {
            np->next = np - (size - 1);
            np->prev = np - 1;
        }
        else {
            np->next = np + 1;
            np->prev = np - 1;
        }

        np->msg.refs = 0;
        np->msg.size = 0;
        np->msg.idx = i+1;
        np->msg.memsize = channel->def_msg_size;
        np->msg.data = ngx_slab_alloc_locked(ctx->shpool,
                                             NGX_HTTP_LUA_IPC_DEFAULT_SIZE);

        if (np->msg.data == NULL) {
            for(int j = i; j >= 0; j--) {
                ngx_slab_free_locked(ctx->shpool, np);

                np--;
            }
            ngx_slab_free_locked(ctx->shpool, channel_node);
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "Failed while allocating messages.");
            return NGX_DECLINED;
        }
        np++;
    }

    ngx_rbtree_insert(&ctx->sh->rbtree, channel_node);

    channel->refs = 1;
    *out = channel;

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}

ngx_http_lua_ipc_list_node_t *
ngx_http_lua_ipc_get_node(ngx_http_lua_ipc_channel_t *ch, int pos)
{
    ngx_http_lua_ipc_list_node_t *tmp;

    if (pos == 0) {
        return ch->head;
    } else if (pos == -1) {
        if (ch->head->msg.unread == 0) {
            return ch->head;
        }
        tmp = ch->head->prev;
        uint32_t idx = tmp->msg.idx;

        while (tmp->prev->msg.idx < idx && tmp->prev->msg.unread > 0) {
            tmp->msg.unread++;
            tmp = tmp->prev;
        }

        tmp->msg.unread++;
        return tmp;
    } else if (pos > 0) {
        /* Note we do NOT verify that the node contains any valid data, as this
         * will be checked upon fetching a message. */
        /*node = channel->head;*/
        /*if (start > node->msg.idx) {*/
            /*ngx_free(subscriber);*/
            /*return NGX_DECLINED;*/
        /*}*/

        /*ngx_uint_t diff = node->msg.idx - start;*/
        /*if (diff > channel->size) {*/
            /*ngx_free(subscriber);*/
            /*return NGX_DECLINED;*/
        /*}*/

        /*if (node - diff < channel->nodes) {*/
            /*diff -= node - channel->nodes;*/
        /*}*/

        /*node = node - diff;*/
    /*} else {*/
        /*return NULL;*/
    }

    return NULL;
}

int
ngx_http_lua_ffi_ipc_channel_subscribe(ngx_http_lua_ipc_channel_t *channel,
    int start, ngx_http_lua_ipc_subscriber_t **out)
{
    ngx_shm_zone_t                   *zone;
    ngx_http_lua_ipc_subscriber_t    *subscriber;
    ngx_http_lua_ipc_ctx_t           *ctx;

    zone = channel->zone;
    if (zone == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "No zone!");
        return NGX_ERROR;
    }

    ctx = (ngx_http_lua_ipc_ctx_t *) zone->data;
    ngx_shmtx_lock(&ctx->shpool->mutex);

    subscriber = ngx_alloc(sizeof(ngx_http_lua_ipc_subscriber_t),
                           ngx_cycle->log);

    if (subscriber == NULL) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                     "ipc_subscribe failed: no memory");
        return NGX_ERROR;
    }

    subscriber->node = ngx_http_lua_ipc_get_node(channel, start);

    if (subscriber->node == NULL) {
        return NGX_ERROR;
    }

    subscriber->idx = subscriber->node->msg.idx;
    subscriber->channel = channel;

    channel->refs++;
    channel->subscribers++;
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "New sub idx: %d", subscriber->idx);
    *out = subscriber;
    ngx_shmtx_unlock(&ctx->shpool->mutex);
    return NGX_OK;
}

int
ngx_http_lua_ipc_next_node(ngx_http_lua_ipc_list_node_t **node)
{
    ngx_http_lua_ipc_list_node_t *tmp;

    uint32_t idx = (*node)->msg.idx;
    tmp = (*node)->next;

    while(tmp->msg.idx > idx && tmp != *node) {
        tmp = tmp->next;
    }

    *node = tmp;

    return tmp->msg.idx - idx;
}

int
ngx_http_lua_ffi_ipc_get_message(ngx_http_lua_ipc_subscriber_t *sub)
{
    ngx_shm_zone_t                 *zone;
    ngx_http_lua_ipc_ctx_t         *ctx;
    ngx_http_lua_ipc_list_node_t   *node;
    ngx_http_lua_ipc_channel_t     *channel;
    uint32_t                        skipped;

    channel = sub->channel;

    if (sub->idx > channel->counter) {
        return NGX_AGAIN;
    }

    zone = channel->zone;
    ctx  = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    node = sub->node;
    if (node->msg.idx != sub->idx) {
        if (channel->flags & NGX_HTTP_LUA_IPC_SAFE) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "Msg idx: %d was lost in safe mode! New idx %d",
                          sub->idx, node->msg.idx);
        }

        skipped = ngx_http_lua_ipc_next_node(&sub->node);
    }
    else {
        skipped = 0;
    }

    sub->skipped = skipped;
    sub->msg = &node->msg;
    sub->idx = node->msg.idx;

    node->msg.refs++;

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}


void ngx_http_lua_ffi_ipc_ack_msg(ngx_http_lua_ipc_subscriber_t *sub) {
    // ack could possibly request a new message, thus eliviating
    // the ngx.sleep loop while new messages are in the queue
    ngx_http_lua_ipc_ctx_t       *ctx;
    ngx_http_lua_ipc_channel_t   *channel;
    ngx_http_lua_ipc_msg_t       *msg;

    channel = sub->channel;
    ctx = channel->zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    msg = sub->msg;

    msg->refs--;
    msg->unread--;
    sub->idx++;
    sub->node = sub->node->next;

    ngx_shmtx_unlock(&ctx->shpool->mutex);
}

void *
ngx_http_lua_ipc_alloc_msg(ngx_http_lua_ipc_list_node_t *node, int safe,
        ngx_http_lua_ipc_ctx_t *ctx, size_t size)
{
    void                         *data = NULL;
    ngx_http_lua_ipc_list_node_t *p = node->next;

    data = ngx_slab_alloc_locked(ctx->shpool, size);

    while (data == NULL && p != node) {
        if(p->msg.refs > 0) {
            p = p->next;
            continue;
        }

        if(safe && p->msg.unread > 0) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "Could not free in safe queue");
            return NULL;
        }

        if (p->msg.data != NULL) {
            ngx_slab_free_locked(ctx->shpool, node->msg.data);
            data = ngx_slab_alloc_locked(ctx->shpool, size);
        }

        p = p->next;
    }

    if (data == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                        "Freed all available space but it's not enough!");
        return NULL;
    }

    return data;
}

int ngx_http_lua_ffi_ipc_add_msg(ngx_http_lua_ipc_channel_t *channel,
    void *msg, ngx_uint_t size)
{
    ngx_http_lua_ipc_list_node_t *node;
    ngx_shm_zone_t               *zone;
    ngx_http_lua_ipc_ctx_t       *ctx;
    void                         *data = NULL;
    uint8_t                       safe;

    zone = channel->zone;
    if (zone == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "No zone!");
        return NGX_ERROR;
    }

    if (size > NGX_HTTP_LUA_IPC_MAX_SIZE) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "msg too large, size: %d, max size: %d", size,
                      NGX_HTTP_LUA_IPC_MAX_SIZE);
        return NGX_ERROR;
    }

    safe = (channel->flags & NGX_HTTP_LUA_IPC_SAFE) ? 1 : 0;

    ctx = (ngx_http_lua_ipc_ctx_t *) zone->data;
    ngx_shmtx_lock(&ctx->shpool->mutex);

    node = channel->head;

    /*
     * Future note: It could be possible to find a node in the list
     * that's not in use and rearrange the order of the list.
     * Wont bother working on it unless it's deemed necessary.
     */

    if (node->msg.refs > 0) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_DECLINED;
    }
    else if (safe && node->msg.unread > 0) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "Can't add to safe queue, still unread");
        return NGX_DECLINED;
    }


    if (node->msg.memsize < size) {
        ngx_slab_free_locked(ctx->shpool, node->msg.data);
        data = ngx_http_lua_ipc_alloc_msg(node, safe, ctx, size);
        if (data == NULL) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_DECLINED;
        }

        node->msg.memsize = size;
    }
    else if (node->msg.memsize > channel->def_msg_size
        && size <= channel->def_msg_size)
    {
        ngx_slab_free_locked(ctx->shpool, node->msg.data);
        data = ngx_http_lua_ipc_alloc_msg(node, safe, ctx, channel->def_msg_size);
        if (data == NULL) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_DECLINED;
        }

        node->msg.memsize = channel->def_msg_size;
    }
    else {
        data = node->msg.data;
    }

    ngx_memcpy(data, msg, size);

    channel->head = channel->head->next;

    node->msg.data = data;
    node->msg.size = size;
    node->msg.idx = ++channel->counter;
    node->msg.size = size;
    node->msg.idx = channel->counter;
    node->msg.unread = channel->subscribers;

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}

static void ngx_http_lua_ipc_decrement_channel_refs(
    ngx_http_lua_ipc_channel_t *channel, ngx_http_lua_ipc_ctx_t *ctx)
{
    ngx_http_lua_ipc_list_node_t *tmp;

    channel->refs--;

    if (channel->flags & NGX_HTTP_LUA_IPC_DESTROY && channel->refs == 0) {
        ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "Destroying channel");

        tmp = channel->head;
        for (; tmp != channel->head; tmp = tmp->next) {
            ngx_slab_free_locked(ctx->shpool, tmp->msg.data);
        }

        ngx_rbtree_node_t *channel_node = channel->channel_node;
        ngx_rbtree_delete(&ctx->sh->rbtree, channel_node);
        ngx_slab_free_locked(ctx->shpool, channel_node);
    }

}

void ngx_http_lua_ffi_ipc_free_channel(
    ngx_http_lua_ipc_channel_t **channel)
{
    ngx_shm_zone_t       *zone;
    ngx_http_lua_ipc_ctx_t *ctx;

    if (*channel == NULL) {
        return;
    }

    zone = (*channel)->zone;
    ctx = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    ngx_http_lua_ipc_decrement_channel_refs(*channel, ctx);

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "decrementing channel refs, current: %d", (*channel)->refs);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return;
}
void ngx_http_lua_ffi_ipc_free_subscriber(
    ngx_http_lua_ipc_subscriber_t **sub)
{
    ngx_shm_zone_t               *zone;
    ngx_http_lua_ipc_ctx_t       *ctx;
    ngx_http_lua_ipc_list_node_t *node;

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "freeing subscriber");

    zone = (*sub)->channel->zone;
    ctx = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    (*sub)->channel->subscribers--;

    ngx_http_lua_ipc_decrement_channel_refs((*sub)->channel, ctx);

    node = (*sub)->node;
    while (node->msg.idx >= (*sub)->idx) {
        node->msg.unread--;
        node = node->next;
    }

    ngx_free(*sub);

    ngx_shmtx_unlock(&ctx->shpool->mutex);
}

static void ngx_http_lua_ipc_rbtree_insert_value(ngx_rbtree_node_t *temp,
       ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel) {
}
