#include "ngx_http_lua_ipc_module.h"

static char* ngx_http_lua_ipc(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_lua_ipc_init(ngx_shm_zone_t *shm_zone, void *data);
static void* ngx_http_ipc_create_main_conf(ngx_conf_t *cf);

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

    NULL,                           /* preconfiguration */
    NULL,                           /* postconfiguration */

	ngx_http_ipc_create_main_conf,  /* create main configuration */
	NULL,
    /*ngx_http_live_init_main_conf,   [> init main configuration <]*/

    NULL,                           /* create server configuration */
    NULL,                           /* merge server configuration */

	NULL,
	NULL,
    /*ngx_http_live_create_loc_conf,  [> create location configuration <]*/
    /*ngx_http_live_merge_loc_conf    [> merge location configuration <]*/
};

ngx_module_t  ngx_http_lua_ipc_module = {
    NGX_MODULE_V1,
    &ngx_http_lua_ipc_module_ctx,      /* module context */
    ngx_http_lua_ipc_cmds,         /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
	NULL,
	NULL,
	/*ngx_http_live_init_module,      [> init module <]*/
	/*ngx_http_live_init_process,     [> init process <]*/
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
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
    /*ngx_http_lua_main_conf_t   *lmcf = conf;*/
    ngx_http_lua_ipc_conf_t   *lmcf = conf;

    ngx_str_t                  *value, name;
    ngx_shm_zone_t             *zone;
    ngx_shm_zone_t            **zp;
    ngx_http_lua_ipc_ctx_t   *ctx;
    ssize_t                     size;

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
    /*ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_lua_shdict_ctx_t));*/
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

	lmcf->requires_shm = 1;

    return NGX_CONF_OK;
}

ngx_int_t
ngx_http_lua_ipc_init(ngx_shm_zone_t *shm_zone, void *data) {
	ngx_http_lua_ipc_ctx_t  *octx = data;

	size_t                   len;
	ngx_http_lua_ipc_ctx_t  *ctx;

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

/*ngx_http_lua_ipc_channel_lookup(zone, &hash, key, key_len, &channel);*/
ngx_int_t
ngx_http_lua_ipc_channel_lookup(ngx_shm_zone_t *zone, ngx_uint_t hash,
		u_char *kdata, size_t klen, ngx_http_lua_ffi_ipc_channel_t **sdp)
{
	ngx_http_lua_ipc_ctx_t  *ctx;
	ngx_rbtree_node_t       *node, *sentinel;
	ngx_http_lua_ffi_ipc_channel_t *sd;
	ngx_int_t                   rc;

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

		sd = (ngx_http_lua_ffi_ipc_channel_t *) &node->data;

		rc = ngx_memn2cmp(kdata, sd->name.data, klen, sd->name.len);

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
ngx_http_lua_ffi_ipc_get_zone(u_char *name, ngx_uint_t len)
{
	ngx_http_lua_ipc_conf_t    *lmcf;
	ngx_shm_zone_t             *p;

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

extern int
ngx_http_lua_ffi_ipc_new(const char *shm_name, const char *chname, size_t size,
	uint8_t safe, uint8_t destroy, ngx_http_lua_ffi_ipc_channel_t **out)
{

	ngx_shm_zone_t             *zone;
	uint32_t                    hash;
	ngx_int_t                   rc;
	ngx_rbtree_node_t          *channel_node;
	ngx_http_lua_ffi_ipc_channel_t *channel;
	size_t                     n;
	ngx_http_lua_ipc_list_node_t *np;


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

		ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "Channel exists");
		ngx_shmtx_unlock(&ctx->shpool->mutex);

		return NGX_OK;
	}


	n = offsetof(ngx_rbtree_node_t, data)
		+ sizeof(ngx_http_lua_ffi_ipc_channel_t)
		+ chlen
		+ size * sizeof(ngx_http_lua_ipc_list_node_t);

	channel_node = ngx_slab_alloc_locked(ctx->shpool, n);

	if (channel_node == NULL) {
		ngx_shmtx_unlock(&ctx->shpool->mutex);

		ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
				"Failed to create channel: no memory");
		return NGX_DECLINED;
	}

	channel = (ngx_http_lua_ffi_ipc_channel_t *) &channel_node->data;

	channel_node->key = hash;
	channel->size = size;
	channel->name.len = chlen;
	channel->name.data = &channel->nodes
		                 + sizeof(ngx_http_lua_ipc_list_node_t **);
	ngx_memcpy(channel->name.data, chname, chlen);
	channel->subscribers = NULL;
	channel->zone = zone;

	if (safe == 1) {
		channel->flags |= NGX_HTTP_LUA_FFI_IPC_SAFE;
	}
	if (destroy == 1) {
		channel->flags |= NGX_HTTP_LUA_FFI_IPC_DESTROY;
	}

	np = (ngx_http_lua_ipc_list_node_t *)&channel->nodes + channel->name.len;
	channel->head = np;

	n = sizeof(ngx_http_lua_ipc_list_node_t);

	for (size_t i = 0; i < size; i++) {
		if (i == 0) {
			np->next = np + n;
			np->prev = np + n * (size - 1);
		}
		else if (i == size - 1) {
			np->next = np - n * (size - 1);
			np->prev = np - n;
		}
		else {
			np->next = np + n;
			np->prev = np - n;
		}

		np->size = 0;
		np->refs = 0;
		np->data = NULL;

		np += n;
	}


	ngx_rbtree_insert(&ctx->sh->rbtree, channel_node);

	channel->refs++;
	*out = channel;

	ngx_shmtx_unlock(&ctx->shpool->mutex);

	return NGX_OK;
}

/*start: -1 = .., 0 newest msg, other that index if in range */
extern int
ngx_http_lua_ffi_ipc_channel_subscribe(ngx_http_lua_ffi_ipc_channel_t *channel,
	uint8_t start)
{
	/*ngx_http_lua_ffi_ipc_channel_t *channel;*/
	ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "subscribing");

	ngx_shm_zone_t                     *zone;
	ngx_http_lua_ipc_subscriber_t      *subscriber;
	ngx_http_lua_ipc_ctx_t             *ctx;
	/*ngx_http_lua_ipc_list_node_t       *head;*/

	zone = channel->zone;
	if (zone == NULL) {
		ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "No zone!");
		return NGX_ERROR;
	}

	ctx = (ngx_http_lua_ipc_ctx_t *) zone->data;
	ngx_shmtx_lock(&ctx->shpool->mutex);

	subscriber = (ngx_http_lua_ipc_subscriber_t *)
		         ngx_slab_alloc_locked(ctx->shpool,
				 sizeof(ngx_http_lua_ipc_subscriber_t));

	if (subscriber == NULL) {
		ngx_shmtx_unlock(&ctx->shpool->mutex);
		ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
				"ipc_subscribe failed: no memory");
		return NGX_ERROR;
	}

	ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "Subscriber created");

	if (start == 0) {
		subscriber->idx = channel->head->idx;
		subscriber->node = channel->head;
	}
	/*else if (start == -1) {*/
		/*//*/
	/*}*/

	if (channel->subscribers == NULL) {
		*channel->subscribers = subscriber;
	}
	else {
		ngx_http_lua_ipc_subscriber_t *s;
		for(s = *channel->subscribers; s->next != NULL; s = s->next) {/*void*/}
		s->next = subscriber;
	}

	subscriber->next = NULL;

	// TODO fix and test this
	/*else if (start > 0) {*/
		/*head = channel->head;*/
		/*if (start > head->idx) {*/
			/*return NGX_DECLINED;*/
		/*}*/

		/*ngx_uint_t diff = head->idx - start;*/
		/*if (diff > channel->size) {*/
			/*return NGX_DECLINED;*/
		/*}*/

		/*diff *= sizeof(ngx_http_lua_ipc_list_node_t);*/

		/*if (head - diff < channel->nodes) {*/
			/*diff -= head - channel->nodes;*/
		/*}*/

		/*ngx_http_lua_ipc_list_node_t *p = head - diff;*/
	/*}*/



	/*subscriber->curr_idx = channel->head.idx;*/
	ngx_shmtx_unlock(&ctx->shpool->mutex);
	return NGX_OK;
}

/*extern int*/
/*ngx_http_lua_ffi_ipc_get(ngx_http_lua_ipc_subscriber_t *sub)*/
/*{*/
	/*//check if ptr->idx matches sub->idx if it does then lock and read.*/
/*}*/






extern int ngx_http_lua_ffi_ipc_add_msg(ngx_http_lua_ffi_ipc_channel_t *channel,
	u_char *msg, ngx_uint_t size)
{
	ngx_http_lua_ipc_list_node_t *node;
	ngx_shm_zone_t               *zone;
	ngx_http_lua_ipc_ctx_t       *ctx;
	void                         *data;
	uint8_t                       safe;

	zone = channel->zone;
	if (zone == NULL) {
		ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "No zone!");
		return NGX_ERROR;
	}

	safe = (channel->flags & NGX_HTTP_LUA_FFI_IPC_SAFE) ? 1 : 0;

	ctx = (ngx_http_lua_ipc_ctx_t *) zone->data;
	ngx_shmtx_lock(&ctx->shpool->mutex);

	node = channel->head->next;

	if (node->refs > 0 && safe) {
		ngx_shmtx_unlock(&ctx->shpool->mutex);
		ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
				"A worker is yet to read next message");
		return NGX_DECLINED;
	}

	node->idx += channel->head->idx + 1;

	if (node->data != NULL) {
		ngx_slab_free_locked(ctx->shpool, node->data);
	}

	data = ngx_slab_alloc_locked(ctx->shpool, size+1);

	if (data == NULL) {
		ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0, "no data bro");
		return NGX_DECLINED;
		if (safe) {
			ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
					"Failed to allocate memory");
			return NGX_DECLINED;
		}

		ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "freeing nodes");

		ngx_http_lua_ipc_list_node_t *p = node->next;
		while (data == NULL) {
			if (p == node) {
				ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
						"Freed all available space but it's not enough!");
				return NGX_DECLINED;
			}

			// can check the size field to check if it's worth freeing the memory
			if (p->refs == 0 && p->data != NULL) {
				ngx_slab_free_locked(ctx->shpool, node->data);
				data = ngx_slab_alloc_locked(ctx->shpool, size);
			}

			p = p->next;
		}
	}

	ngx_memcpy(data, msg, size);

	node->data = data;
	node->size = size;

	channel->head = node;

	ngx_shmtx_unlock(&ctx->shpool->mutex);

	return NGX_OK;
}


extern void ngx_http_lua_ffi_ipc_free_channel(
	ngx_http_lua_ffi_ipc_channel_t **channel)
{
	ngx_shm_zone_t         *zone;
	ngx_http_lua_ipc_ctx_t *ctx;

	if (*channel == NULL) {
		return;
	}

	zone = (*channel)->zone;
	//ifelse

	ctx = zone->data;

	ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "freeing channel");

	ngx_shmtx_lock(&ctx->shpool->mutex);

	(*channel)->refs--;

	if ((*channel)->flags & NGX_HTTP_LUA_FFI_IPC_DESTROY
		&& (*channel)->refs == 0)
	{
		ngx_slab_free_locked(ctx->shpool, *channel);
	}

	/*ngx_free(channel);*/

	ngx_shmtx_unlock(&ctx->shpool->mutex);

	return;
}
extern int ngx_http_lua_ffi_ipc_free_subscriber(
	ngx_http_lua_ipc_subscriber_t **subscriber)
{
	ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "freeing subscriber");
	return 0;
}

void ngx_http_lua_ipc_rbtree_insert_value(ngx_rbtree_node_t *temp,
       ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel) {
}
