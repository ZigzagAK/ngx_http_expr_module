#include <ngx_config.h>
#include <ngx_http.h>


typedef struct {
    ngx_array_t  vars;
    ngx_str_t    key;
    ngx_uint_t   hash;
    ngx_int_t    max_size;
} ngx_http_expr_loc_conf_t;


typedef struct {
    ngx_http_expr_loc_conf_t  *elcf;
    ngx_http_complex_value_t   cv;
    ngx_flag_t                 if_empty;
    size_t                     len;
    u_char                     data[1];
} ngx_http_expr_t;


typedef struct {
    ngx_int_t               index;
    ngx_str_t               name;
    ngx_hash_keys_arrays_t  keys;
    ngx_hash_t              hash;
} ngx_http_expr_var_t;


static ngx_int_t
ngx_http_expr_get(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static void *ngx_http_expr_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_expr_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static ngx_int_t ngx_http_expr_init(ngx_conf_t *cf);


static char *
ngx_http_expr(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_expr_commands[] = {

    { ngx_string("expr"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_expr,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("expr_if_empty"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_expr,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("expr_max_hash_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_expr_loc_conf_t, max_size),
      NULL },

      ngx_null_command

};


static ngx_http_module_t  ngx_http_expr_module_ctx = {
    NULL,                           /* preconfiguration */
    ngx_http_expr_init,             /* postconfiguration */

    NULL,                           /* create main configuration */
    NULL,                           /* init main configuration */

    NULL,                           /* create server configuration */
    NULL,                           /* merge server configuration */

    ngx_http_expr_create_loc_conf,  /* create location configuration */
    ngx_http_expr_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_expr_module = {
    NGX_MODULE_V1,
    &ngx_http_expr_module_ctx,    /* module context */
    ngx_http_expr_commands,       /* module directives */
    NGX_HTTP_MODULE,              /* module type */
    NULL,                         /* init master */
    NULL,                         /* init module */
    NULL,                         /* init process */
    NULL,                         /* init thread */
    NULL,                         /* exit thread */
    NULL,                         /* exit process */
    NULL,                         /* exit master */
    NGX_MODULE_V1_PADDING
};


static void
ngx_http_expr_set(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
        "can't change variable introduced by \"expr directive\"");
}


static ngx_int_t
ngx_http_expr_get_raw(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data)
{
    ngx_http_expr_loc_conf_t  *elcf;
    ngx_http_expr_t           *expr;
    ngx_http_expr_var_t       *v;

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_expr_module);
    v = (ngx_http_expr_var_t *) data;

    expr = ngx_hash_find(&v->hash, elcf->hash, elcf->key.data, elcf->key.len);
    if (expr != NULL) {

        if (!vv->valid || !expr->if_empty) {
            vv->data = (u_char *) &expr->data;
            vv->len = expr->len;
            vv->valid = 1;
            vv->not_found = 0;
        }

        return NGX_OK;
    }

    vv->valid = 0;
    vv->not_found = 1;

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_expr_get(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_expr_t            *expr;
    ngx_str_t                   vv;
    ngx_http_variable_value_t  *raw_vv;

    raw_vv = ngx_http_get_indexed_variable(r, data);
    if (raw_vv == NULL || !raw_vv->valid)
        return NGX_ERROR;

    expr = (ngx_http_expr_t *) (raw_vv->data - offsetof(ngx_http_expr_t, data));

    if (ngx_http_complex_value(r, &expr->cv, &vv) == NGX_OK) {

        v->data = vv.data;
        v->len = vv.len;
        v->valid = 1;
        v->not_found = 0;

        return NGX_OK;
    }

    v->valid = 0;

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_expr_hex(ngx_pool_t *pool, ngx_str_t *res, void *data, size_t len)
{
    res->len = len << 1;
    res->data = ngx_palloc(pool, res->len);
    if (res->data == NULL)
        return NGX_ERROR;

    ngx_hex_dump(res->data, data, len);

    return NGX_OK;
}


static char *
ngx_http_expr(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_expr_loc_conf_t           *elcf = conf;
    ngx_http_variable_t                *var;
    ngx_http_variable_t                *var_raw;
    ngx_str_t                           var_raw_name;
    ngx_str_t                          *args = cf->args->elts;
    ngx_http_compile_complex_value_t    ccv;
    ngx_http_expr_var_t                *v;
    ngx_http_expr_t                    *expr;
    static ngx_str_t                    if_empty = ngx_string("expr_if_empty");

    if (args[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &args[1]);
        return NGX_CONF_ERROR;
    }

    args[1].len--;
    args[1].data++;

    if (ngx_http_expr_hex(cf->pool, &var_raw_name, args[1].data, args[1].len)
            == NGX_ERROR)
        goto nomem;

    var_raw = ngx_http_add_variable(cf, &var_raw_name, NGX_HTTP_VAR_CHANGEABLE);
    if (var_raw == NULL)
        return NGX_CONF_ERROR;

    var = ngx_http_add_variable(cf, &args[1],
        NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL)
        return NGX_CONF_ERROR;

    v = ngx_array_push(&elcf->vars);
    if (v == NULL)
        goto nomem;

    ngx_memzero(v, sizeof(ngx_http_expr_var_t));

    v->index = ngx_http_get_variable_index(cf, &var_raw_name);

    if (var_raw->data == 0) {
        v->name = args[1];
        v->keys.pool = cf->pool;
        v->keys.temp_pool = cf->temp_pool;
        ngx_hash_keys_array_init(&v->keys, NGX_HASH_SMALL);
        var_raw->data = (uintptr_t) v;
    } else
        v = (ngx_http_expr_var_t *) var_raw->data;

    var->data = v->index;

    expr = ngx_pcalloc(cf->pool, sizeof(ngx_http_expr_t) + args[2].len);
    if (expr == NULL)
        goto nomem;

    if (elcf->hash == 0) {
        if (ngx_http_expr_hex(cf->pool, &elcf->key, elcf, sizeof(elcf))
                == NGX_ERROR)
            goto nomem;
        elcf->hash = ngx_hash_key(elcf->key.data, elcf->key.len);
    }

    ngx_hash_add_key(&v->keys, &elcf->key, expr, NGX_HASH_READONLY_KEY);

    expr->if_empty = ngx_memn2cmp(args[0].data, if_empty.data, args[0].len, if_empty.len) == 0;

    expr->len = args[2].len;
    ngx_memcpy(&expr->data, args[2].data, args[2].len);
    expr->elcf = elcf;

    ngx_memzero(&ccv, sizeof(ccv));

    ccv.cf = cf;
    ccv.value = &args[2];
    ccv.complex_value = &expr->cv;
    ccv.zero = 0;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "can't compile '%V'", &args[2]);
        return NGX_CONF_ERROR;
    }

    var->get_handler = ngx_http_expr_get;
    var->set_handler = ngx_http_expr_set;
    var_raw->get_handler = ngx_http_expr_get_raw;
    var_raw->set_handler = ngx_http_expr_set;

    return NGX_CONF_OK;

nomem:

    ngx_conf_log_error(NGX_LOG_CRIT, cf, 0, "no memory");
    return NGX_CONF_ERROR;

}


static void *
ngx_http_expr_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_expr_loc_conf_t  *elcf;

    elcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_expr_loc_conf_t));
    if (elcf == NULL) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, 0, "no memory");
        return NULL;
    }

    if (ngx_array_init(&elcf->vars, cf->pool, 1, sizeof(ngx_http_expr_var_t))
            == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, 0, "no memory");
        return NULL;
    }

    elcf->max_size = NGX_CONF_UNSET;

    return elcf;
}


static char *
ngx_http_expr_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_expr_loc_conf_t  *conf = child;
    ngx_http_expr_loc_conf_t  *prev = parent;
    ngx_http_expr_var_t       *vars;
    ngx_hash_init_t            hash;
    ngx_uint_t                 i;

    ngx_conf_merge_value(conf->max_size, prev->max_size, 1024);

    vars = conf->vars.elts;

    for (i = 0; i < conf->vars.nelts; i++) {

        if (vars[i].keys.keys.elts == NULL)
            continue;

        hash.hash = &vars[i].hash;
        hash.key = ngx_hash_key;
        hash.max_size = ngx_min(256, conf->max_size);
        hash.bucket_size = ngx_align(64, ngx_cacheline_size);
        hash.name = ngx_pcalloc(cf->pool, vars[i].name.len + 1);
        ngx_memcpy(hash.name, vars[i].name.data, vars[i].name.len);
        hash.pool = cf->pool;
        hash.temp_pool = cf->temp_pool;

        ngx_hash_init(&hash, vars[i].keys.keys.elts, vars[i].keys.keys.nelts);
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_expr_handler(ngx_http_request_t *r)
{
    ngx_http_expr_loc_conf_t  *elcf;
    ngx_http_expr_var_t       *vars;
    ngx_uint_t                 i;

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_expr_module);
    vars = elcf->vars.elts;

    for (i = 0; i < elcf->vars.nelts; i++)
        (void) ngx_http_get_flushed_variable(r, vars[i].index);

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_expr_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL)
        return NGX_ERROR;

    *h = ngx_http_expr_handler;

    return NGX_OK;
}
