/*
 * Copyright (C) 2023 BigfootACA <classfun@classfun.cn>
 *
 * Based on nginx's 'ngx_http_auth_basic_module.c' by Igor Sysoev
 *
 * File: ngx_http_auth_cookie_module.c
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <json-c/json.h>
#include <ngx_crypt.h>

#ifndef RESDIR
#define RESDIR "objs"
#endif
extern ngx_module_t ngx_http_auth_cookie_module;
extern char data_login_html_start;
extern char data_login_html_end;
__asm__(
	".section \".rodata\", \"a\", @progbits\n"
	"data_login_html_start:\n"
	".incbin \""RESDIR"/login.html\"\n"
	"data_login_html_end:\n"
	".previous\n"
);

#define json_add(obj, key, val) { \
	if (!(val)) return NGX_HTTP_INTERNAL_SERVER_ERROR;\
	int _r = json_object_object_add((obj), (key), (val)); \
	if (_r != 0) return NGX_HTTP_INTERNAL_SERVER_ERROR; \
}
#define json_get_str(obj, key, str) { \
	struct json_object *_val;\
	if (!(_val = json_object_object_get(obj, key))) \
		return NGX_HTTP_INTERNAL_SERVER_ERROR; \
	if (!json_object_is_type(_val, json_type_string)) \
		return NGX_HTTP_INTERNAL_SERVER_ERROR; \
	if (!(str = json_object_get_string(_val))) \
		return NGX_HTTP_INTERNAL_SERVER_ERROR; \
}
#define json_get_ngx_str(pool, obj, key, str) { \
	off_t _len; \
	const char *_str = NULL; \
	json_get_str(obj, key, _str); \
	ngx_str_null(str); \
	if ((_len = ngx_strlen(_str)) > 0) { \
		(str)->len = _len, str->data = ngx_pcalloc(pool, _len + 1); \
		if (!str->data) return NGX_HTTP_INTERNAL_SERVER_ERROR; \
		(void)ngx_copy(str->data, _str, _len); \
	} \
}
#define json_add_ngx_str(obj, key, str, def) { \
	ngx_str_t _val = ngx_str_def(str, def); \
	json_add(obj, key, ngx_str_to_json(&_val)); \
}
#define json_add_bool(obj, key, val) json_add(obj, key, json_object_new_boolean(val))
#define json_add_uint64(obj, key, val) json_add(obj, key, json_object_new_uint64(val))
#define json_add_string(obj, key, val) json_add(obj, key, json_object_new_string(val))

static inline struct json_object* ngx_str_to_json(ngx_str_t *v) {
	return v->data ? json_object_new_string_len((const char*)v->data, (int)v->len) : json_object_new_null();
}

static inline ngx_str_t ngx_str_def(ngx_str_t val, const char *def) {
	ngx_str_t ret = val;
	if (!val.data) ngx_memzero(&ret, sizeof(ret));
	if (def) ret.len = ngx_strlen(def), ret.data = (u_char*)def;
	return ret;
}

static inline ngx_flag_t ngx_flag_def(ngx_flag_t val, ngx_flag_t def) {
	return val != NGX_CONF_UNSET ? val : def;
}

typedef struct {
	ngx_str_t title;
	#define DEF_CONF_TITLE       "Login"
	ngx_str_t auth_url;
	#define DEF_CONF_AUTH_URL    "/auth"
	ngx_str_t cookie;
	#define DEF_CONF_COOKIE      "ngx_cookie_auth_token"
	ngx_str_t algo;
	#define DEF_CONF_ALGO        "plain"
	ngx_str_t auth_store;
	#define DEF_CONF_AUTH_STORE  "/tmp/.ngx_auth_cookie_store"
	ngx_http_complex_value_t *user_file;
} ngx_http_auth_cookie_loc_conf_t;

ngx_str_t ngx_http_auth_get_arg(
	ngx_http_request_t *r,
	const char *name
) {
	u_char *p, *e;
	ngx_str_t ret, key, args, arg;
	ngx_str_null(&ret);
	if (r->args.len <= 0) return ret;
	args = r->args, arg = args;
	do {
		p = ngx_strlchr(args.data, args.data + args.len, '&');
		arg.data = args.data, arg.len = p ? (size_t)(p - arg.data) : args.len;
		e = ngx_strlchr(arg.data, arg.data + arg.len, '='), key = arg;
		if (e) key.len = e - key.data;
		if (ngx_strncasecmp((u_char*)name, key.data, key.len) == 0) {
			if(e) ret.data = e + 1, ret.len = arg.len - key.len - 1;
			else ret.data = (u_char*)"";
			return ret;
		}
		if (p) args.data = p + 1, args.len -= arg.len + 1;
	} while (p);
	return ret;
}

static ngx_str_t ngx_http_auth_random_id(ngx_http_request_t *r){
	ngx_str_t str;
	ngx_str_null(&str);
	str.data = ngx_pnalloc(r->pool, 32);
	if (!str.data) return str;
	str.len = 32;
	ngx_sprintf(
		str.data, "%08xD%08xD%08xD%08xD",
		(uint32_t) ngx_random(), (uint32_t) ngx_random(),
		(uint32_t) ngx_random(), (uint32_t) ngx_random()
	);
	return str;
}

static ngx_int_t ngx_http_auth_crypt_handler(
	ngx_http_request_t *r,
	ngx_str_t *pw,
	ngx_str_t *username,
	ngx_str_t *password
) {
	ngx_int_t rc;
	u_char *encrypted = NULL;
	rc = ngx_crypt(
		r->pool,
		password->data,
		pw->data,
		&encrypted
	);
	ngx_log_debug3(
		NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		"rc: %i user: \"%V\" salt: \"%s\"",
		rc, username, pw->data
	);
	if (rc != NGX_OK) return NGX_HTTP_INTERNAL_SERVER_ERROR;
	if (ngx_strcmp(encrypted, pw->data) == 0) return NGX_OK;
	ngx_log_error(
		NGX_LOG_ERR, r->connection->log, 0,
		"user \"%V\": password mismatch", username
	);
	return NGX_HTTP_UNAUTHORIZED;
}

static ngx_int_t ngx_http_auth_handler(
	ngx_http_request_t *r,
	ngx_str_t *username,
	ngx_str_t *password
) {
	ssize_t n;
	ngx_fd_t fd;
	ngx_int_t rc;
	ngx_err_t err;
	ngx_file_t file;
	u_char buf[4096];
	off_t offset = 0;
	ngx_str_t pwd, user_file;
	ngx_uint_t i, level, login = 0, left = 0, passwd = 0;
	ngx_http_auth_cookie_loc_conf_t *conf;
	enum {sw_login, sw_passwd, sw_skip} state = sw_login;
	conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_cookie_module);
	if (!conf->user_file) return NGX_DECLINED;
	if (!username->data || username->len <= 0) return NGX_ERROR;
	if (!password->data || password->len <= 0) return NGX_ERROR;
	if (ngx_http_complex_value(r, conf->user_file, &user_file) != NGX_OK) return NGX_ERROR;
	fd = ngx_open_file(user_file.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
	if (fd == NGX_INVALID_FILE) {
		err = ngx_errno;
		if (err == NGX_ENOENT) level = NGX_LOG_ERR,rc = NGX_HTTP_FORBIDDEN;
		else level = NGX_LOG_CRIT, rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
		ngx_log_error(
			level, r->connection->log, err,
			ngx_open_file_n " \"%s\" failed", user_file.data
		);
		return rc;
	}
	ngx_memzero(&buf, sizeof(buf));
	ngx_memzero(&file, sizeof(ngx_file_t));
	file.fd = fd, file.name = user_file, file.log = r->connection->log;
	for (;;) {
		i = left, n = ngx_read_file(&file, buf + left, 4096 - left, offset);
		if (n == NGX_ERROR) {
			rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
			goto cleanup;
		}
		if (n == 0) break;
		for (i = left; i < left + n; i++) switch (state) {
			case sw_login:
				if (login == 0) {
					if (buf[i] == '#' || buf[i] == CR) {
						state = sw_skip;
						break;
					}
					if (buf[i] == LF) break;
				}
				if (buf[i] != username->data[login]) {
					state = sw_skip;
					break;
				}
				login++;
				if (login == username->len) state = sw_passwd, i += 2, passwd = i;
			break;
			case sw_passwd:
				if (buf[i] == LF || buf[i] == CR || buf[i] == ':') {
					buf[i] = '\0', pwd.len = i - passwd, pwd.data = &buf[passwd];
					rc = ngx_http_auth_crypt_handler(r, &pwd, username, password);
					goto cleanup;
				}
			break;
			case sw_skip:
				if (buf[i] == LF) state = sw_login, login = 0;
			break;
		}
		if (state == sw_passwd) {
			left = left + n - passwd;
			ngx_memmove(buf, &buf[passwd], left);
			passwd = 0;
		} else left = 0;
		offset += n;
	}
	if (state == sw_passwd) {
		pwd.len = i - passwd, pwd.data = ngx_pnalloc(r->pool, pwd.len + 1);
		if (!pwd.data) return NGX_HTTP_INTERNAL_SERVER_ERROR;
		ngx_cpystrn(pwd.data, &buf[passwd], pwd.len + 1);
		rc = ngx_http_auth_crypt_handler(r, &pwd, username, password);
		goto cleanup;
	}
	ngx_log_error(
		NGX_LOG_ERR, r->connection->log, 0,
		"user \"%V\" was not found in \"%s\"",
		username, user_file.data
	);
	rc = NGX_HTTP_UNAUTHORIZED;
	cleanup:
	ngx_close_file(file.fd);
	ngx_explicit_memzero(buf, 4096);
	return rc;
}

static ngx_int_t ngx_http_auth_go_login_page(
	ngx_http_request_t *r,
	ngx_http_auth_cookie_loc_conf_t *conf
) {
	u_char *end;
	uintptr_t escape;
	ngx_str_t uri, dst, param;
	ngx_str_t auth_url = ngx_str_def(conf->auth_url, DEF_CONF_AUTH_URL);

	// escape origin url
	escape = ngx_escape_uri(
		NULL,
		r->unparsed_uri.data, r->unparsed_uri.len,
		NGX_ESCAPE_URI_COMPONENT
	) * 2;
	uri.data = (u_char*)ngx_pcalloc(r->pool, escape + r->unparsed_uri.len);
	if (!uri.data) return NGX_HTTP_INTERNAL_SERVER_ERROR;
	end = escape ? (u_char*)ngx_escape_uri(
		uri.data,
		r->unparsed_uri.data, r->unparsed_uri.len,
		NGX_ESCAPE_URI_COMPONENT
	) : ngx_copy(uri.data, r->unparsed_uri.data, r->unparsed_uri.len);
	if (!end) return NGX_HTTP_INTERNAL_SERVER_ERROR;

	// concatenate url (eg. /auth?action=page&redirect=%2Fmain.php)
	ngx_str_set(&param, "?action=page&redirect=");
	uri.len = end - uri.data;
	dst.len = auth_url.len + param.len + uri.len;
	dst.data = (u_char*)ngx_pcalloc(r->pool, dst.len);
	if (!dst.data) return NGX_HTTP_INTERNAL_SERVER_ERROR;
	end = ngx_cpymem(dst.data, auth_url.data, auth_url.len);
	end = ngx_cpymem(end, param.data, param.len);
	end = ngx_cpymem(end, uri.data, uri.len);
	(void)end;

	// redirect to login page
	ngx_http_clear_location(r);
	r->headers_out.location = ngx_list_push(&r->headers_out.headers);
	if (!r->headers_out.location) return NGX_HTTP_INTERNAL_SERVER_ERROR;
	r->headers_out.location->hash = 1;
	ngx_str_set(&r->headers_out.location->key, "Location");
	r->headers_out.location->value = dst;
	return NGX_HTTP_TEMPORARY_REDIRECT;
}

static ngx_int_t ngx_http_auth_return(
	ngx_http_request_t *r,
	ngx_str_t type,
	u_char *content,
	off_t length
) {
	ngx_buf_t *b;
	ngx_int_t rc;
	ngx_chain_t out;
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = length;
	r->headers_out.content_type = type;
	r->headers_out.content_type_len = type.len;
	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
	b = ngx_calloc_buf(r->pool);
	if (!b) return NGX_ERROR;
	b->pos = content;
	b->last = content + length;
	b->memory = 1;
	b->last_buf = (r == r->main) ? 1 : 0;
	b->last_in_chain = 1;
	out.buf = b;
	out.next = NULL;
	return ngx_http_output_filter(r, &out);
}

static ngx_int_t ngx_http_auth_return_json(
	ngx_http_request_t *r,
	json_object *jo
) {
	ngx_int_t rc;
	size_t len = 0;
	const char *buff = NULL;
	if (!jo) return NGX_HTTP_INTERNAL_SERVER_ERROR;
	buff = json_object_to_json_string_length(jo, 0, &len);
	if (!buff) return NGX_HTTP_INTERNAL_SERVER_ERROR;
	rc = ngx_http_auth_return(
		r, (ngx_str_t)ngx_string("application/json; charset=utf-8"),
		(u_char*)buff, (off_t)len
	);
	json_object_put(jo);
	return rc;
}

static ngx_int_t ngx_http_auth_login_page(ngx_http_request_t *r) {
	if (ngx_http_discard_request_body(r) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	return ngx_http_auth_return(
		r, (ngx_str_t)ngx_string("text/html; charset=utf-8"),
		(u_char*)&data_login_html_start,
		&data_login_html_end - &data_login_html_start
	);
}

static ngx_int_t ngx_http_auth_config(ngx_http_request_t *r) {
	ngx_http_auth_cookie_loc_conf_t *conf;
	conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_cookie_module);
	if (ngx_http_discard_request_body(r) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	struct json_object *jo = json_object_new_object();
	json_add_bool(jo, "success", 1);
	json_add_ngx_str(jo, "title", conf->title, DEF_CONF_TITLE);
	json_add_ngx_str(jo, "algo", conf->algo, DEF_CONF_ALGO);
	return ngx_http_auth_return_json(r, jo);
}

static ngx_int_t ngx_http_auth_get_login(
	ngx_http_request_t *r,
	ngx_http_auth_cookie_loc_conf_t *conf,
	struct json_object *data,
	ngx_str_t *username,
	ngx_str_t *password
) {
	const char *str;
	ngx_str_t algo = ngx_str_def(conf->algo, DEF_CONF_ALGO);
	json_get_str(data, "algo", str);
	if (ngx_strncasecmp((u_char*)str, algo.data, algo.len) != 0) return NGX_ERROR;
	json_get_ngx_str(r->pool, data, "username", username);
	json_get_ngx_str(r->pool, data, "password", password);
	return NGX_OK;
}

static ngx_int_t ngx_http_auth_write_cookie(
	ngx_http_request_t *r,
	ngx_str_t token
) {
	u_char *p;
	ngx_table_elt_t *elt;
	ngx_str_t field, cookie;
	ngx_http_auth_cookie_loc_conf_t *conf;
	conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_cookie_module);
	cookie = ngx_str_def(conf->cookie, DEF_CONF_COOKIE);
	field.len = cookie.len + 1 + token.len;
	field.data = ngx_pcalloc(r->pool, field.len + 1);
	if (!field.data) return NGX_ERROR;
	p = ngx_cpymem(field.data, cookie.data, cookie.len);
	p = ngx_cpymem(p, "=", 1);
	p = ngx_cpymem(p, token.data, token.len);
	(void)p;
	if (!(elt = ngx_list_push(&r->headers_out.headers))) return NGX_ERROR;
	elt->hash = 1;
	ngx_str_set(&elt->key, "Set-Cookie");
	elt->value = field;
	return NGX_OK;
}

static ngx_int_t ngx_http_auth_write_json(
	ngx_http_request_t *r,
	ngx_str_t username,
	ngx_str_t token,
	ngx_file_t *file
) {
	ssize_t s;
	const char *d;
	size_t len = 0;
	struct json_object *jo;
	ngx_int_t rc = NGX_ERROR;
	ngx_time_update();
	if (!(jo = json_object_new_object())) return NGX_ERROR;
	json_add_ngx_str(jo, "token", token, NULL);
	if (username.data && username.len > 0)
		json_add_ngx_str(jo, "username", username, NULL);
	json_add_uint64(jo, "time", ngx_time());
	d = json_object_to_json_string_length(jo, 0, &len);
	if (d && len > 0){
		s = ngx_write_file(file, (u_char*)d, len, 0);
		if (s > 0 && len == (size_t)s) rc = NGX_OK;
		else ngx_log_debug2(
			NGX_LOG_DEBUG, r->connection->log, 0,
			"wrote json mismatch %zu != %zd", len, s
		);
	} else ngx_log_debug0(
		NGX_LOG_WARN, r->connection->log, 0,
		"generate json failed"
	);
	json_object_put(jo);
	return rc;
}

static ngx_int_t ngx_http_auth_write_token(
	ngx_http_request_t *r,
	ngx_str_t username,
	ngx_str_t *token
) {
	u_char *p;
	ngx_file_t file;
	ngx_file_info_t sb;
	ngx_int_t rc = NGX_ERROR;
	ngx_str_t auth_store, path;
	ngx_http_auth_cookie_loc_conf_t *conf;
	conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_cookie_module);
	auth_store = ngx_str_def(conf->auth_store, DEF_CONF_AUTH_STORE);
	ngx_create_dir(auth_store.data, 0700);
	path.len = auth_store.len + 38;
	path.data = ngx_palloc(r->pool, path.len + 1);
	if (!path.data) return NGX_ERROR;
	ngx_memzero(token, sizeof(ngx_str_t));
	do {
		if (token->len != 0) ngx_log_debug0(
			NGX_LOG_WARN, r->connection->log, 0,
			"retry generate token"
		);
		*token = ngx_http_auth_random_id(r);
		if (token->len != 32) {
			ngx_log_debug0(
				NGX_LOG_WARN, r->connection->log, 0,
				"generate token failed"
			);
			return NGX_ERROR;
		}
		ngx_memzero(path.data, path.len + 1);
		p = ngx_cpymem(path.data, auth_store.data, auth_store.len);
		p = ngx_cpymem(p, "/auth-", 6);
		p = ngx_cpymem(p, token->data, token->len);
		(void)p;
	} while (ngx_file_info(path.data, &sb) != NGX_ERROR);
	file.name = path, file.log = r->connection->log;
	file.fd = ngx_open_file(path.data, NGX_FILE_RDWR, NGX_FILE_TRUNCATE, 0600);
	if (file.fd == NGX_INVALID_FILE) {
		ngx_log_debug1(
			NGX_LOG_WARN, r->connection->log, ngx_errno,
			"open auth token \"%V\" failed", token
		);
		return NGX_ERROR;
	}
	rc = ngx_http_auth_write_json(r, username, *token, &file);
	ngx_close_file(file.fd);
	if (rc != NGX_OK) return NGX_ERROR;
	rc = ngx_http_auth_write_cookie(r, *token);
	return rc == NGX_OK ? NGX_OK : NGX_ERROR;
}

static ngx_int_t ngx_http_auth_do_proc_login(ngx_http_request_t *r) {
	u_char *p;
	ngx_int_t rc;
	off_t len = 0;
	char buffer[4096];
	ngx_chain_t *in, *bufs;
	struct json_object *jo, *data;
	ngx_str_t username, password, token;
	ngx_http_auth_cookie_loc_conf_t *conf;
	ngx_str_null(&username);
	ngx_str_null(&password);
	conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_cookie_module);
	if (!r->request_body) return NGX_HTTP_INTERNAL_SERVER_ERROR;
	bufs = r->request_body->bufs;
	for (in = bufs; in; in = in->next) len += ngx_buf_size(in->buf);
	if (len <= 0 || len >= 4096) return NGX_HTTP_BAD_REQUEST;
	ngx_memzero(buffer, sizeof(buffer));
	for (in = bufs, p = (u_char*)buffer; in; in = in->next)
		p = ngx_copy(p, in->buf->pos, in->buf->last - in->buf->pos);
	data = json_tokener_parse(buffer);
	ngx_explicit_memzero(buffer, sizeof(buffer));
	if (!data) return NGX_HTTP_BAD_REQUEST;
	rc = ngx_http_auth_get_login(r,conf, data, &username, &password);
	json_object_put(data);
	jo = json_object_new_object();
	if (rc != NGX_OK) {
		json_add_bool(jo, "success", 0);
		json_add_string(jo, "message", "invalid request");
	} else if (ngx_http_auth_handler(r, &username, &password) != NGX_OK) {
		json_add_bool(jo, "success", 0);
		json_add_string(jo, "message", "auth failed");
	} else if (ngx_http_auth_write_token(r, username, &token) != NGX_OK) {
		json_add_bool(jo, "success", 0);
		json_add_string(jo, "message", "auth token error");
	} else {
		json_add_bool(jo, "success", 1);
		json_add_ngx_str(jo, "token", token, NULL);
	}
	return ngx_http_auth_return_json(r, jo);
}

static void ngx_http_auth_proc_login(ngx_http_request_t *r) {
	ngx_http_finalize_request(r, ngx_http_auth_do_proc_login(r));
}

static ngx_int_t ngx_http_auth_login(ngx_http_request_t *r) {
	ngx_int_t rc;
	if (
		r->method != NGX_HTTP_POST ||
		!r->headers_in.content_length ||
		r->headers_in.content_length_n <= 0 ||
		r->headers_in.content_length_n >= 4096
	) return NGX_HTTP_BAD_REQUEST;
	rc = ngx_http_read_client_request_body(r, ngx_http_auth_proc_login);
	return rc >= NGX_HTTP_SPECIAL_RESPONSE ? rc : NGX_DONE;
}

static ngx_int_t ngx_http_auth_req(ngx_http_request_t *r) {
	ngx_str_t action = ngx_http_auth_get_arg(r, "action");
	if(action.data && action.len > 0) {
		if(ngx_strncasecmp((u_char*)"page", action.data, action.len) == 0)
			return ngx_http_auth_login_page(r);
		else if(ngx_strncasecmp((u_char*)"config", action.data, action.len) == 0)
			return ngx_http_auth_config(r);
		else if(ngx_strncasecmp((u_char*)"login", action.data, action.len) == 0)
			return ngx_http_auth_login(r);
	}
	return NGX_HTTP_BAD_REQUEST;
}

static ngx_int_t ngx_http_auth_check_token(ngx_http_request_t *r, ngx_str_t val) {
	size_t i;
	ssize_t s;
	ngx_file_t file;
	u_char *p, buf[4096];
	const char *token = NULL;
	struct json_object *jo, *v;
	ngx_str_t auth_store, path;
	ngx_http_auth_cookie_loc_conf_t *conf;
	conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_cookie_module);
	auth_store = ngx_str_def(conf->auth_store, DEF_CONF_AUTH_STORE);
	if (!val.data || val.len != 32) return NGX_ERROR;
	for (i = 0; i < val.len; i++) switch(val.data[i]){
		case '0' ... '9': case 'a' ... 'f': break;
		default: return NGX_ERROR;
	}
	path.len = auth_store.len + 6 + val.len;
	path.data = ngx_pcalloc(r->pool, path.len + 1);
	if (!path.data) return NGX_ERROR;
	p = ngx_cpymem(path.data, auth_store.data, auth_store.len);
	p = ngx_cpymem(p, "/auth-", 6);
	p = ngx_cpymem(p, val.data, val.len);
	(void)p;
	ngx_memzero(&file, sizeof(file));
	file.name = path, file.log = r->connection->log;
	file.fd = ngx_open_file(path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
	if (file.fd == NGX_INVALID_FILE) {
		ngx_log_debug1(
			NGX_LOG_DEBUG, r->connection->log, ngx_errno,
			"open auth token \"%V\" failed", val
		);
		return NGX_ERROR;
	}
	ngx_memzero(buf,sizeof(buf));
	s = ngx_read_file(&file, buf, sizeof(buf), 0);
	ngx_close_file(file.fd);
	if (s == NGX_ERROR || s <= 0 || (size_t)s >= sizeof(buf)) {
		ngx_log_debug1(
			NGX_LOG_WARN, r->connection->log, ngx_errno,
			"read auth token \"%V\" failed", val
		);
		return NGX_ERROR;
	}
	if (!(jo = json_tokener_parse((char*)buf))) {
		ngx_log_debug1(
			NGX_LOG_WARN, r->connection->log, 0,
			"parse auth token \"%V\" failed", val
		);
		return NGX_ERROR;
	}
	json_get_str(jo, "token", token);
	if (!token || ngx_strncmp(token, val.data, val.len) != 0) {
		ngx_log_debug1(
			NGX_LOG_WARN, r->connection->log, 0,
			"auth token \"%V\" mismatch", val
		);
		return NGX_ERROR;
	}
	if ((v = json_object_object_get(jo, "expires"))) {
		ngx_time_update();
		if ((uint64_t)ngx_time() > json_object_get_uint64(v)) {
			ngx_log_debug1(
				NGX_LOG_DEBUG, r->connection->log, 0,
				"auth token \"%V\" expires", val
			);
			return NGX_ERROR;
		}
	}

	ngx_log_debug1(
		NGX_LOG_DEBUG, r->connection->log, 0,
		"auth token \"%V\" valid", val
	);
	return NGX_OK;
}

static ngx_int_t ngx_http_auth_cookie_handler(ngx_http_request_t *r) {
	ngx_int_t rc;
	ngx_str_t auth_url, cookie, val;
	ngx_http_auth_cookie_loc_conf_t *conf;
	conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_cookie_module);
	auth_url = ngx_str_def(conf->auth_url, DEF_CONF_AUTH_URL);
	cookie = ngx_str_def(conf->cookie, DEF_CONF_COOKIE);
	ngx_str_null(&val);

	// handle login page
	if (
		r->uri.len > 0 && r->uri.len == auth_url.len &&
		ngx_strncmp(r->uri.data, auth_url.data, r->uri.len) == 0
	) return ngx_http_auth_req(r);

	// check cookie
	rc = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &cookie, &val);
	if (rc != NGX_DECLINED && ngx_http_auth_check_token(r, val) == NGX_OK) return NGX_DECLINED;

	// go to login page
	return ngx_http_auth_go_login_page(r, conf);
}

static ngx_int_t ngx_http_auth_cookie_init(ngx_conf_t *cf) {
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t *cmcf;
	ngx_log_error(NGX_ERROR_ERR,cf->log,0,"on init");
	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (!h) return NGX_ERROR;
	*h = ngx_http_auth_cookie_handler;
	return NGX_OK;
}

static void *ngx_http_auth_cookie_create_loc_conf(ngx_conf_t *cf) {
	ngx_http_auth_cookie_loc_conf_t *conf;
	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_cookie_loc_conf_t));
	if (!conf) return NGX_CONF_ERROR;
	conf->user_file = NGX_CONF_UNSET_PTR;
	return conf;
}

static char *ngx_http_auth_cookie_merge_loc_conf(
	ngx_conf_t *cf __attribute_maybe_unused__,
	void *parent, void *child
) {
	ngx_http_auth_cookie_loc_conf_t *prev = parent, *conf = child;
	ngx_conf_merge_str_value(conf->title, prev->title, DEF_CONF_TITLE);
	ngx_conf_merge_str_value(conf->auth_url, prev->auth_url, DEF_CONF_AUTH_URL);
	ngx_conf_merge_str_value(conf->algo, prev->algo, DEF_CONF_ALGO);
	ngx_conf_merge_str_value(conf->cookie, prev->cookie, DEF_CONF_COOKIE);
	ngx_conf_merge_ptr_value(conf->user_file, prev->user_file, NULL);
	ngx_conf_merge_str_value(conf->auth_store, prev->auth_store, NULL);
	return NGX_CONF_OK;
}

static char *ngx_http_auth_cookie_complex(
	ngx_conf_t *cf,
	ngx_command_t *cmd __attribute_maybe_unused__,
	void *c
) {
	ngx_http_auth_cookie_loc_conf_t *conf = c;
	ngx_http_compile_complex_value_t ccv;
	ngx_str_t *value;
	if (conf->user_file != NGX_CONF_UNSET_PTR) return "is duplicate";
	conf->user_file = ngx_pcalloc(cf->pool, sizeof(ngx_http_complex_value_t));
	if (!conf->user_file) return NGX_CONF_ERROR;
	value = cf->args->elts;
	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
	ccv.cf = cf, ccv.value = &value[1];
	ccv.complex_value = conf->user_file;
	ccv.zero = 1, ccv.conf_prefix = 1;
	return ngx_http_compile_complex_value(&ccv) != NGX_OK ? NGX_CONF_ERROR : NGX_CONF_OK;
}

static ngx_command_t ngx_http_auth_cookie_commands[] = {
	{
		ngx_string("auth_cookie"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_cookie_loc_conf_t, title), NULL
	}, {
		ngx_string("auth_cookie_user_file"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
		ngx_http_auth_cookie_complex, NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_cookie_loc_conf_t, user_file), NULL
	}, {
		ngx_string("auth_cookie_store"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_cookie_loc_conf_t, auth_store), NULL
	}, {
		ngx_string("auth_cookie_url"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_cookie_loc_conf_t, auth_url), NULL
	}, {
		ngx_string("auth_cookie_key"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_cookie_loc_conf_t, cookie), NULL
	},
	ngx_null_command
};

static ngx_http_module_t ngx_http_auth_cookie_module_ctx = {
	NULL,                                  /* pre configuration */
	ngx_http_auth_cookie_init,             /* post configuration */
	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */
	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */
	ngx_http_auth_cookie_create_loc_conf,  /* create location configuration */
	ngx_http_auth_cookie_merge_loc_conf,   /* merge location configuration */
};

ngx_module_t ngx_http_auth_cookie_module = {
	NGX_MODULE_V1,
	&ngx_http_auth_cookie_module_ctx,      /* module context */
	ngx_http_auth_cookie_commands,         /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,                                  /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};
