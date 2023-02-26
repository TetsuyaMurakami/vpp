/*
 * sr_mbile_util_sr_table.h
 *
 */

#ifndef _PTREE_H_
#define _PTREE_H_
typedef int (*sr_table_del_cb_t) (void *info);

/* Error code */
#define PTREE_SUCCESS		0
#define PTREE_FAILURE		-1
#define PTREE_DELETE_FAILURE	-2

struct sr_table_node {
    struct sr_table_node 	*link[2];
#define left_child  link[0]
#define right_child link[1]

    struct sr_table 	    *table;
    struct sr_table_node 	*parent;

    void		        *info;

    _Atomic u32         lock;

    u8		            active;
#define PTREE_NODE_INACTIVE	0
#define PTREE_NODE_ACTIVE	1

    u8      		    padding[2];

    u8      		    key_len;
    u8      		    key[0];
};

struct sr_table {
    struct sr_table_node 	*top;
    u8      		    family;
    u8      		    max_key_len;
    u8      		    max_key_siz;

    sr_table_del_cb_t	    delete_cb;
};

struct sr_table * sr_table_new (u8 family, u8 max_keylen, sr_table_del_cb_t del);
int sr_table_delete (struct sr_table *table, int force);

void sr_table_node_lock (struct sr_table_node *node);
int sr_table_node_unlock (struct sr_table_node *node);

struct sr_table_node *sr_table_node_new (struct sr_table *table, u8 *key, u8 keylen);
struct sr_table_node *sr_table_node_get (struct sr_table *table, u8 *key, u8 keylen);

struct sr_table_node *sr_table_node_lookup (struct sr_table *table, u8 *key, u8 keylen);
struct sr_table_node *sr_table_node_match (struct sr_table *table, u8 *key, u8 keylen);

int sr_table_node_delete (struct sr_table *table, struct sr_table_node *node);
int sr_table_node_release (struct sr_table *table, u8 *key, u8 keylen);

struct sr_table_node *sr_table_top (struct sr_table *table);
struct sr_table_node *sr_table_node_next (struct sr_table_node *node);

void *sr_table_node_get_data (struct sr_table_node *node);
void *sr_table_node_set_data (struct sr_table_node *node, void *data);

u_int8_t *sr_table_node_key (struct sr_table_node *node);
u_int8_t sr_table_node_key_len (struct sr_table_node *node);

#endif /* _PTREE_H_ */
