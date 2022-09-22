
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdio.h>
#include <string.h>
#include <xdb_searcher.h>

xdb_content_t *c_buffer;
typedef struct
{
    ngx_str_t region; /* unsigned  deny:1; */
} ngx_ip2region_access_rule_t;

typedef struct
{
    ngx_array_t *rules; /* array of ngx_ip2region_access_rule_t */
} ngx_ip2region_access_loc_conf_t;

static ngx_int_t ngx_ip2region_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_ip2region_access_init(ngx_conf_t *cf);
static char *ngx_ip2region_access_rule(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf);
static void *ngx_ip2region_access_create_loc_conf(ngx_conf_t *cf);
static char *ngx_ip2region_access_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static ngx_command_t ngx_ip2region_access_commands[] = {
    {ngx_string("allow_region"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
     ngx_ip2region_access_rule,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},
    ngx_null_command};

static ngx_http_module_t ngx_ip2region_access_module_ctx = {
    NULL,                 /* preconfiguration */
    ngx_ip2region_access_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_ip2region_access_create_loc_conf, /* create location configuration */
    ngx_ip2region_access_merge_loc_conf  /* merge location configuration */
};

ngx_module_t ngx_ip2region_access_module = {
    NGX_MODULE_V1,
    &ngx_ip2region_access_module_ctx, /* module context */
    ngx_ip2region_access_commands,    /* module directives */
    NGX_HTTP_MODULE,             /* module type */
    NULL,                        /* init master */
    NULL,                        /* init module */
    NULL,                        /* init process */
    NULL,                        /* init thread */
    NULL,                        /* exit thread */
    NULL,                        /* exit process */
    NULL,                        /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_int_t
ngx_ip2region_access_handler(ngx_http_request_t *r)
{
    ngx_ip2region_access_loc_conf_t *alcf;
    ngx_ip2region_access_rule_t *rule;
    ngx_uint_t i;
    alcf = ngx_http_get_module_loc_conf(r, ngx_ip2region_access_module);
    int err = 0;
    xdb_searcher_t searcher;
    xdb_new_with_buffer(&searcher, c_buffer);
    unsigned int ip;
    char region[512] = {'\0'};
    ngx_str_t ipaddr_t = r->connection->addr_text;
    char *ipaddr = (char *)(ipaddr_t.data);
    if (xdb_check_ip(ipaddr, &ip) != 0)
    {
        xdb_close(&searcher);
        return NGX_HTTP_FORBIDDEN;
    }
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "ip %i", ip);
    err = xdb_search(&searcher, ip, region, sizeof(region));
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "err %i", err);
    xdb_close(&searcher);
    if (err != 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "xdb_search err %i", err);
        return NGX_HTTP_FORBIDDEN;
    }
    else
    {
        if (alcf->rules)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "has rule");
            rule = alcf->rules->elts;
            for (i = 0; i < alcf->rules->nelts; i++)
            {
                ngx_str_t allow_region = rule[i].region;
                if (strstr(region, (char *)(allow_region.data)))
                {
                    return NGX_OK;
                }
            }
        }
    }
    return NGX_HTTP_FORBIDDEN;
}

static ngx_int_t
ngx_ip2region_access_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL)
    {
        return NGX_ERROR;
    }

    *h = ngx_ip2region_access_handler;
    c_buffer = xdb_load_content_from_file("/home/ubuntu/lib/ip2region.xdb");

    return NGX_OK;
}
static char *
ngx_ip2region_access_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_ip2region_access_loc_conf_t *alcf = conf;

    ngx_str_t                  *value;
    ngx_ip2region_access_rule_t     *rule;


    value = cf->args->elts;



        if (alcf->rules == NULL) {
            alcf->rules = ngx_array_create(cf->pool, 4,
                                           sizeof(ngx_ip2region_access_rule_t));
            if (alcf->rules == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        rule = ngx_array_push(alcf->rules);
        if (rule == NULL) {
            return NGX_CONF_ERROR;
        }
        rule->region = value[1];
    return NGX_CONF_OK;
}

static void *
ngx_ip2region_access_create_loc_conf(ngx_conf_t *cf)
{
    ngx_ip2region_access_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_ip2region_access_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_ip2region_access_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_ip2region_access_loc_conf_t  *prev = parent;
    ngx_ip2region_access_loc_conf_t  *conf = child;

    if (conf->rules == NULL
    ) {
        conf->rules = prev->rules;
    }

    return NGX_CONF_OK;
}