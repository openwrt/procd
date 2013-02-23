#include <sys/stat.h>

#include <libgen.h>
#include <regex.h>

#include <json/json.h>
#include <libubox/avl-cmp.h>
#include <libubox/blobmsg_json.h>

#include "hotplug.h"

static struct blob_buf b;

static int rule_process_expr(struct blob_attr *cur, struct blob_attr *msg);
static int rule_process_cmd(struct blob_attr *cur, struct blob_attr *msg);

static char *__msg_find_var(struct blob_attr *msg, const char *name)
{
	struct blob_attr *cur;
	int rem;

	blob_for_each_attr(cur, msg, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			continue;

		if (strcmp(blobmsg_name(cur), name) != 0)
			continue;

		return blobmsg_data(cur);
	}

	return NULL;
}

static char *msg_find_var(struct blob_attr *msg, const char *name)
{
	char *str;

	if (!strcmp(name, "DEVICENAME") || !strcmp(name, "DEVNAME")) {
		str = __msg_find_var(msg, "DEVPATH");
		if (!str)
			return NULL;

		return basename(str);
	}

	return __msg_find_var(msg, name);
}

static void
rule_get_tuple(struct blob_attr *cur, struct blob_attr **tb, int t1, int t2)
{
	static struct blobmsg_policy expr_tuple[3] = {
		{ .type = BLOBMSG_TYPE_STRING },
		{},
		{},
	};

	expr_tuple[1].type = t1;
	expr_tuple[2].type = t2;
	blobmsg_parse_array(expr_tuple, 3, tb, blobmsg_data(cur), blobmsg_data_len(cur));
}

static int handle_if(struct blob_attr *expr, struct blob_attr *msg)
{
	struct blob_attr *tb[4];
	int ret;

	static const struct blobmsg_policy if_tuple[4] = {
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_ARRAY },
		{ .type = BLOBMSG_TYPE_ARRAY },
		{ .type = BLOBMSG_TYPE_ARRAY },
	};

	blobmsg_parse_array(if_tuple, 4, tb, blobmsg_data(expr), blobmsg_data_len(expr));

	if (!tb[1] || !tb[2])
		return 0;

	ret = rule_process_expr(tb[1], msg);
	if (ret < 0)
		return 0;

	if (ret)
		return rule_process_cmd(tb[2], msg);

	if (!tb[3])
		return 0;

	return rule_process_cmd(tb[3], msg);
}

static int handle_case(struct blob_attr *expr, struct blob_attr *msg)
{
	struct blob_attr *tb[3], *cur;
	const char *var;
	int rem;

	rule_get_tuple(expr, tb, BLOBMSG_TYPE_STRING, BLOBMSG_TYPE_TABLE);
	if (!tb[1] || !tb[2])
		return 0;

	var = msg_find_var(msg, blobmsg_data(tb[1]));
	if (!var)
		return 0;

	blobmsg_for_each_attr(cur, tb[2], rem) {
		if (!strcmp(var, blobmsg_name(cur)))
			return rule_process_cmd(cur, msg);
	}

	return 0;
}

static int handle_return(struct blob_attr *expr, struct blob_attr *msg)
{
	return -2;
}

static int handle_include(struct blob_attr *expr, struct blob_attr *msg)
{
	struct blob_attr *tb[3];
	struct rule_file *r;

	rule_get_tuple(expr, tb, BLOBMSG_TYPE_STRING, 0);
	if (!tb[1])
		return 0;

	r = rule_file_get(blobmsg_data(tb[1]));
	if (!r)
		return 0;

	return rule_process_cmd(r->data, msg);
}

static const struct rule_handler cmd[] = {
	{ "if", handle_if },
	{ "case", handle_case },
	{ "return", handle_return },
	{ "include", handle_include },
};

static int eq_regex_cmp(const char *str, const char *pattern, bool regex)
{
	regex_t reg;
	int ret;

	if (!regex)
		return !strcmp(str, pattern);

	if (regcomp(&reg, pattern, REG_EXTENDED | REG_NOSUB))
		return 0;

	ret = !regexec(&reg, str, 0, NULL, 0);
	regfree(&reg);

	return ret;
}

static int expr_eq_regex(struct blob_attr *expr, struct blob_attr *msg, bool regex)
{
	struct blob_attr *tb[3], *cur;
	const char *var;
	int rem;

	rule_get_tuple(expr, tb, BLOBMSG_TYPE_STRING, 0);
	if (!tb[1] || !tb[2])
		return -1;

	var = msg_find_var(msg, blobmsg_data(tb[1]));
	if (!var)
		return 0;

	switch(blobmsg_type(tb[2])) {
	case BLOBMSG_TYPE_STRING:
		return eq_regex_cmp(var, blobmsg_data(tb[2]), regex);
	case BLOBMSG_TYPE_ARRAY:
		blobmsg_for_each_attr(cur, tb[2], rem) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING) {
				rule_error(cur, "Unexpected element type");
				return -1;
			}

			if (eq_regex_cmp(var, blobmsg_data(cur), regex))
				return 1;
		}
		return 0;
	default:
		rule_error(tb[2], "Unexpected element type");
		return -1;
	}
}

static int handle_expr_eq(struct blob_attr *expr, struct blob_attr *msg)
{
	return expr_eq_regex(expr, msg, false);
}

static int handle_expr_regex(struct blob_attr *expr, struct blob_attr *msg)
{
	return expr_eq_regex(expr, msg, true);
}

static int handle_expr_has(struct blob_attr *expr, struct blob_attr *msg)
{
	struct blob_attr *tb[3], *cur;
	int rem;

	rule_get_tuple(expr, tb, 0, 0);
	if (!tb[1])
		return -1;

	switch(blobmsg_type(tb[1])) {
	case BLOBMSG_TYPE_STRING:
		return !!msg_find_var(msg, blobmsg_data(tb[1]));
	case BLOBMSG_TYPE_ARRAY:
		blobmsg_for_each_attr(cur, tb[1], rem) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING) {
				rule_error(cur, "Unexpected element type");
				return -1;
			}

			if (msg_find_var(msg, blobmsg_data(cur)))
				return 1;
		}
		return 0;
	default:
		rule_error(tb[1], "Unexpected element type");
		return -1;
	}
}

static int expr_and_or(struct blob_attr *expr, struct blob_attr *msg, bool and)
{
	struct blob_attr *cur;
	int ret, rem;
	int i = 0;

	blobmsg_for_each_attr(cur, expr, rem) {
		if (i++ < 1)
			continue;

		ret = rule_process_expr(cur, msg);
		if (ret < 0)
			return ret;

		if (ret != and)
			return ret;
	}

	return and;
}

static int handle_expr_and(struct blob_attr *expr, struct blob_attr *msg)
{
	return expr_and_or(expr, msg, 1);
}

static int handle_expr_or(struct blob_attr *expr, struct blob_attr *msg)
{
	return expr_and_or(expr, msg, 0);
}

static int handle_expr_not(struct blob_attr *expr, struct blob_attr *msg)
{
	struct blob_attr *tb[3];

	rule_get_tuple(expr, tb, BLOBMSG_TYPE_ARRAY, 0);
	if (!tb[1])
		return -1;

	return rule_process_expr(tb[1], msg);
}

static const struct rule_handler expr[] = {
	{ "eq", handle_expr_eq },
	{ "regex", handle_expr_regex },
	{ "has", handle_expr_has },
	{ "and", handle_expr_and },
	{ "or", handle_expr_or },
	{ "not", handle_expr_not },
};

static int
__rule_process_type(struct blob_attr *cur, struct blob_attr *msg,
		    const struct rule_handler *h, int n, bool *found)
{
	const char *name = blobmsg_data(blobmsg_data(cur));
	int i;

	for (i = 0; i < n; i++) {
		if (strcmp(name, h[i].name) != 0)
			continue;

		*found = true;
		return h[i].handler(cur, msg);
	}

	*found = false;
	return -1;
}

static int rule_process_expr(struct blob_attr *cur, struct blob_attr *msg)
{
	bool found;
	int ret;

	if (blobmsg_type(cur) != BLOBMSG_TYPE_ARRAY ||
	    blobmsg_type(blobmsg_data(cur)) != BLOBMSG_TYPE_STRING) {
		rule_error(cur, "Unexpected element type");
		return -1;
	}

	ret = __rule_process_type(cur, msg, expr, ARRAY_SIZE(expr), &found);
	if (!found)
		rule_error(cur, "Unknown expression type");

	return ret;
}

static void cmd_add_string(const char *pattern, struct blob_attr *msg)
{
	char *dest, *next, *str;
	int len = 0;
	bool var = false;

	dest = blobmsg_alloc_string_buffer(&b, NULL, 1);
	str = alloca(strlen(pattern) + 1);
	strcpy(str, pattern);
	next = str;

	while (*str) {
		const char *cur;
		int cur_len = 0;

		next = strchr(str, '%');
		if (!next)
			next = str + strlen(str);

		if (var) {
			if (next > str) {
				*next = 0;
				cur = msg_find_var(msg, str);
				if (cur)
					cur_len = strlen(cur);
			} else {
				cur = str - 1;
				cur_len = 1;
			}
		} else {
			cur = str;
			cur_len = next - str;
		}

		if (cur_len) {
			dest = blobmsg_realloc_string_buffer(&b, cur_len + 1);
			memcpy(dest + len, cur, cur_len);
			len += cur_len;
		}

		var = !var;
		str = next + 1;
	}

	dest[len] = 0;
	blobmsg_add_string_buffer(&b);
}

static int cmd_process_strings(struct blob_attr *attr, struct blob_attr *msg)
{
	struct blob_attr *cur;
	int args = -1;
	int rem;
	void *c;

	blob_buf_init(&b, 0);
	c = blobmsg_open_array(&b, NULL);
	blobmsg_for_each_attr(cur, attr, rem) {
		if (args++ < 0)
			continue;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING) {
			rule_error(attr, "Invalid argument in command");
			return -1;
		}

		cmd_add_string(blobmsg_data(cur), msg);
	}

	blobmsg_close_array(&b, c);

	return 0;
}

static int __rule_process_cmd(struct blob_attr *cur, struct blob_attr *msg)
{
	const char *name;
	bool found;
	int ret;

	if (blobmsg_type(cur) != BLOBMSG_TYPE_ARRAY ||
	    blobmsg_type(blobmsg_data(cur)) != BLOBMSG_TYPE_STRING) {
		rule_error(cur, "Unexpected element type");
		return -1;
	}

	ret = __rule_process_type(cur, msg, cmd, ARRAY_SIZE(cmd), &found);
	if (found)
		return ret;

	name = blobmsg_data(blobmsg_data(cur));
	ret = cmd_process_strings(cur, msg);
	if (ret)
		return ret;

	rule_handle_command(name, blob_data(b.head));

	return 0;
}

static int rule_process_cmd(struct blob_attr *block, struct blob_attr *msg)
{
	struct blob_attr *cur;
	int rem;
	int ret;
	int i = 0;

	if (blobmsg_type(block) != BLOBMSG_TYPE_ARRAY) {
		rule_error(block, "Unexpected element type");
		return -1;
	}

	blobmsg_for_each_attr(cur, block, rem) {
		switch(blobmsg_type(cur)) {
		case BLOBMSG_TYPE_STRING:
			if (!i)
				return __rule_process_cmd(block, msg);
		default:
			ret = rule_process_cmd(cur, msg);
			if (ret < -1)
				return ret;
			break;
		}
		i++;
	}

	return 0;
}

void rule_process_msg(struct rule_file *f, struct blob_attr *msg)
{
	rule_process_cmd(f->data, msg);
}

static struct rule_file *
rule_file_load(const char *filename)
{
	struct rule_file *r;
	struct stat st;

	json_object *obj = NULL;

	blob_buf_init(&b, 0);

	if (stat(filename, &st))
		return NULL;

	obj = json_object_from_file((char *) filename);
	if (is_error(obj))
		return NULL;

	if (!json_object_is_type(obj, json_type_array)) {
		json_object_put(obj);
		return NULL;
	}

	blobmsg_add_json_element(&b, filename, obj);
	json_object_put(obj);

	r = calloc(1, sizeof(*r) + blob_len(b.head));
	memcpy(r->data, blob_data(b.head), blob_len(b.head));
	r->avl.key = blobmsg_name(r->data);

	return r;
}

static struct avl_tree rule_files;

struct rule_file *
rule_file_get(const char *filename)
{
	struct rule_file *r;

	if (!rule_files.comp)
		avl_init(&rule_files, avl_strcmp, false, NULL);

	r = avl_find_element(&rule_files, filename, r, avl);
	if (r)
		return r;

	r = rule_file_load(filename);
	if (!r)
		return NULL;

	avl_insert(&rule_files, &r->avl);
	return r;
}

void
rule_file_free_all(void)
{
	struct rule_file *r, *next;

	avl_remove_all_elements(&rule_files, r, avl, next)
		free(r);

	blob_buf_free(&b);
}
