#include "ngx_http_lua_ipc_module.h"

// non-header functions from ngx_lua
ngx_shm_zone_t *
ngx_http_lua_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name, size_t size,
    void *tag);


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
		u_char *kdata, size_t klen, ngx_http_lua_ipc_channel_t **sdp)
{
	ngx_http_lua_ipc_ctx_t  *ctx;
	ngx_rbtree_node_t       *node, *sentinel;
	ngx_http_lua_ipc_channel_t *sd;
	ngx_int_t                   rc;

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

		ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
				"hello");
		rc = ngx_memn2cmp(kdata, sd->name, klen, sd->name_len);
		ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
				"goobye");


		if (rc == 0) {
			*sdp = sd;
		ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
				"goobye");

			return NGX_OK;
		}

		node = (rc < 0) ? node->left : node->right;
	}

	*sdp = NULL;

	return NGX_DECLINED;
}

extern int
ngx_http_lua_ipc_new(u_char *shm_name, u_char *chname, size_t size, ngx_http_lua_ipc_channel_t **out)
{
	ngx_shm_zone_t             *zone = NULL;
	ngx_http_lua_ipc_conf_t    *lmcf;
	/*ngx_http_lua_ipc_shctx_t   *shctx;*/
	uint32_t                    hash;
	ngx_int_t                   rc;
	ngx_rbtree_node_t          *channel_node;
	ngx_http_lua_ipc_channel_t *channel;
	ngx_uint_t                  n;
	ngx_http_lua_ipc_list_node_t *np;

	ngx_uint_t shm_nlen = strlen((const char *)shm_name);
	ngx_uint_t chlen = strlen((const char *)chname);

	lmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
			                                   ngx_http_lua_ipc_module);
	if (!lmcf) {
		ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
				"Failed to get module config");
		return NGX_ERROR;
	}

	// Check if zone exists
	ngx_shm_zone_t *p = *(ngx_shm_zone_t**)lmcf->shdict_zones->elts;

	for (ngx_uint_t i=0; i < lmcf->shdict_zones->nelts; i++) {
		if (shm_nlen == p->shm.name.len &&
			ngx_strncmp(shm_name, p->shm.name.data, shm_nlen) == 0)
		{
			zone = p;
			break;
		}

		p += lmcf->shdict_zones->size;
	}


	if (zone == NULL) {
		ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
				"Could not find shared zone: %s", shm_name);
		return NGX_ERROR;
	}

	ngx_http_lua_ipc_ctx_t *ctx = (ngx_http_lua_ipc_ctx_t *) zone->data;
	ngx_shmtx_lock(&ctx->shpool->mutex);

	//check if channel exists
	ngx_crc32_init(hash);
	ngx_crc32_update(&hash, (u_char*) chname, chlen);
	ngx_crc32_final(hash);

	rc = ngx_http_lua_ipc_channel_lookup(zone, hash, chname, chlen, &channel);

	if(rc == NGX_OK) {
		*out = channel;

		ngx_shmtx_unlock(&ctx->shpool->mutex);

		return NGX_OK;
		/* assign the channel to some input struct and retrieve in luajit */
	}

	n = offsetof(ngx_rbtree_node_t, data)
		+ sizeof(ngx_http_lua_ipc_list_node_t)
		+ chlen
		+ size * sizeof(ngx_http_lua_ipc_list_node_t);

	channel_node = (ngx_rbtree_node_t *) ngx_slab_alloc_locked(ctx->shpool, n);

	if (channel_node == NULL) {
		ngx_shmtx_unlock(&ctx->shpool->mutex);

		ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
				"Failed to create channel: no memory");
		return NGX_DECLINED;
	}

	channel = (ngx_http_lua_ipc_channel_t *) &channel_node->data;

	channel_node->key = hash;
	channel->name_len = chlen;
	channel->size = size;
	ngx_memcpy(&channel->nodes + sizeof(ngx_http_lua_ipc_list_node_t **),
			   chname, chlen);
	channel->name = &channel->nodes + sizeof(ngx_http_lua_ipc_list_node_t **);
	channel->subscribers = NULL;

	np = (ngx_http_lua_ipc_list_node_t *)channel + offsetof(ngx_http_lua_ipc_channel_t, nodes) + channel->name_len;
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
		np->ref_count = 0;
		np->data = NULL;

		np += n;
	}

	ngx_rbtree_insert(&ctx->sh->rbtree, channel_node);

	*out = channel;

	ngx_shmtx_unlock(&ctx->shpool->mutex);

	return NGX_OK;
}

extern int ngx_http_lua_ffi_ipc_channel_free(ngx_http_lua_ipc_channel_t **channel)
{
	
}

void ngx_http_lua_ipc_rbtree_insert_value(ngx_rbtree_node_t *temp,
	ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel) {

}
