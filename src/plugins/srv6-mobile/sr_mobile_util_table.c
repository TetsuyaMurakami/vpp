/*
 * sr_mbile_util_sr_table.c
 *
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <vnet/vnet.h>

#include "sr_mobile_util_table.h"

static const u_int8_t mask_bit[] = {
    0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff
};

/* Create a new prefix table */
struct sr_table *
sr_table_new (u_int8_t family, u_int8_t max_keylen, sr_table_del_cb_t del)
{
    struct sr_table *table;

    table = clib_mem_alloc (sizeof (struct sr_table));
    if (! table) {
        return NULL;
    }

    clib_memset (table, 0, sizeof(*table));

    table->family = family;
    table->max_key_len = max_keylen;

    table->max_key_siz = (max_keylen >> 3);
    if ((max_keylen & 0x7) != 0) {
        table->max_key_siz++;
    }

    table->delete_cb = del;

    return table;
}

/* Destroy the prefix table */
int
sr_table_delete (struct sr_table *table, int force)
{
    struct sr_table_node *node, *next;

    if (force == 0) {
        if (table->top != NULL) {
            return PTREE_DELETE_FAILURE;
        }
    } else {
        for (node = sr_table_top(table); node != NULL; node = next) {
            next = sr_table_node_next (node);
	        node->lock = 0;
            sr_table_node_unlock (node);
        }
    }

    clib_mem_free (table);
    return PTREE_SUCCESS;
}

/* Lock the node in a given prefix table */
void
sr_table_node_lock (struct sr_table_node *node)
{
    clib_atomic_fetch_add (&node->lock, 1);
}

/* Unlock the node in a given prefix table and then delete the node if the lock is 0 */
int
sr_table_node_unlock (struct sr_table_node *node)
{
    struct sr_table *table;

    if (node->lock != 0)
        clib_atomic_fetch_sub (&node->lock, 1);

    if (node->lock == 0) {
        table = node->table;

        if (table->delete_cb && node->info) {
            table->delete_cb (node->info);
            node->info = NULL;
        }

        sr_table_node_delete (table, node);
        return 1;
    }

    return 0;
}

/* Crate a new node in a given prefix table */
struct sr_table_node *
sr_table_node_new (struct sr_table *table, u_int8_t *key, u_int8_t keylen)
{
    size_t size;
    struct sr_table_node *node;

    size = sizeof (struct sr_table_node) + table->max_key_siz; 

    node = clib_mem_alloc (size);
    if (! node) {
        return NULL;
    }

    clib_memset (node, 0, size);

    node->key_len = keylen;
    memcpy (node->key, key, table->max_key_siz);

    node->table = table;

    return node;
}

/* Create a new node in a given prefix table with the intermidiate node */
struct sr_table_node *
sr_table_node_base (struct sr_table *table, struct sr_table_node *node, u_int8_t *key, u_int8_t keylen)
{
    int i, j;
    int boundary = 0;
    u_int8_t len;
    u_int8_t diff;
    u_int8_t mask = 0x80;
    size_t size;
    struct sr_table_node *new;

    for (i = 0; i < keylen/8; i++) {
        if (node->key[i] != key[i]) {
            break;
        }
    }

    len = i * 8;
    if (keylen != len) {
        diff = node->key[i] ^ key[i];
        for (; (len < keylen) && ((diff & mask) == 0); len++) {
            boundary = 1;
            mask = mask >> 1;
        }
    }

    size = sizeof (struct sr_table_node) + table->max_key_siz;

    new = clib_mem_alloc (size);
    if (! new) {
        return NULL;
    }

    clib_memset (new, 0, size);

    new->table = table;

    new->key_len = len;
    for (j = 0; j < i; j++) {
        new->key[j] = node->key[j];
    }

    if (boundary != 0) {
        new->key[j] = node->key[j] & mask_bit[new->key_len & 0x7];
    }

    return new;
}

/* Compare the keys */
int
sr_table_node_key_match (u_int8_t *k1, u_int8_t k1len, u_int8_t *k2, u_int8_t k2len)
{
    int offset, shift;
    u_int8_t key, mask;

    if (k1len > k2len) {
        return 0;
    }

    offset = k1len >> 3;
    shift = k1len & 0x7;

    if (shift > 0) {
        key = k1[offset] ^ k2[offset];
        mask = key & mask_bit[shift];
        if (mask != 0) {
            return 0;
        }
    }

    while (offset != 0) {
        offset--;
        if (k1[offset] != k2[offset]) {
            return 0;
        }
    }

    return 1;
}

/* Decide either right or left child as the next node */
int
sr_table_node_check_bit (u_int8_t *key, u_int8_t keylen)
{
    int offset, shift;
    u_int8_t bit;

    offset = keylen >> 3;
    shift = 7 - (keylen & 0x7);

    bit = key[offset] >> shift;
    bit = bit & 0x01;

    return (int)bit;
}

/* Set the link for a given node */
void
sr_table_node_set_link (struct sr_table_node *n1, struct sr_table_node *n2)
{
    int bit;

    bit = sr_table_node_check_bit (n2->key, n1->key_len);

    n1->link[bit] = n2;
    n2->parent = n1;
}

/* Get the node in a given prefix table. If not present, a new node is created */
struct sr_table_node *
sr_table_node_get (struct sr_table *table, u_int8_t *key, u_int8_t keylen)
{
    struct sr_table_node *match = NULL;
    struct sr_table_node *node;
    struct sr_table_node *new;
    struct sr_table_node *n;

    if (keylen > table->max_key_len) {
        return NULL;
    }

    node = table->top;
    while (node != NULL && node->key_len <= keylen) {
        if (sr_table_node_key_match (node->key, node->key_len, key, keylen)) {
            if (node->key_len == keylen) {
                if (node->active != PTREE_NODE_ACTIVE) {
                     node->active = PTREE_NODE_ACTIVE;
                }
                sr_table_node_lock (node);
                return node;
            } else {
                match = node;
                node = node->link[sr_table_node_check_bit(key, node->key_len)];
            }
        } else {
            break;
        }
    }

    if (node == NULL) {
        new = sr_table_node_new (table, key, keylen);
        if (! new) {
            return NULL;
        }

        if (match != NULL) {
            sr_table_node_set_link (match, new);
        } else {
            table->top = new;
        }
    } else {
        new = sr_table_node_base (table, node, key, keylen);
        if (! new) {
            return NULL;
        }

        sr_table_node_set_link (new, node);

        if (match != NULL) {
            sr_table_node_set_link (match, new);
        } else {
            table->top = new;
        }

        if (new->key_len != keylen) {
          n = sr_table_node_new (table, key, keylen);
          sr_table_node_set_link (new, n);
          new = n;
        }
    }

    sr_table_node_lock (new);

    new->active = PTREE_NODE_ACTIVE;

    return new;
}

/* Exact match */
struct sr_table_node *
sr_table_node_lookup (struct sr_table *table, u_int8_t *key, u_int8_t keylen)
{
    struct sr_table_node *node;

    if (keylen > table->max_key_len) {
        return NULL;
    }

    node = table->top;
    while (node != NULL && node->key_len <= keylen) {
        if (sr_table_node_key_match (node->key, node->key_len, key, keylen)) {
            if (node->key_len == keylen) {
                if (node->active == PTREE_NODE_ACTIVE) {
                    sr_table_node_lock(node);
                    return node;
                } else {
                    return NULL;
                }
            } else {
                node = node->link[sr_table_node_check_bit(key, node->key_len)];
            }
        } else {
            break;
        }
    }

    return NULL;
}

/* Longest match */
struct sr_table_node *
sr_table_node_match (struct sr_table *table, u_int8_t *key, u_int8_t keylen)
{
    struct sr_table_node *node;
    struct sr_table_node *match = NULL;
    
    if (keylen > table->max_key_len) {
        return NULL;
    }
    
    node = table->top;
    while (node != NULL && node->key_len <= keylen) {
        if (sr_table_node_key_match (node->key, node->key_len, key, keylen)) {
            match = node;
            node = node->link[sr_table_node_check_bit(key, node->key_len)];
        } else {
            break;
        }
    }

    if ((match == NULL) || (match->active != PTREE_NODE_ACTIVE)) {
        return NULL;
    }

    sr_table_node_lock (match);
    return match;
}

/* Delete the node in a given prefix table */
int
sr_table_node_delete (struct sr_table *table, struct sr_table_node *node)
{
    struct sr_table_node *parent;
    struct sr_table_node *child;

    assert (node->lock == 0);
    assert (node->info == NULL);

    node->active = PTREE_NODE_INACTIVE;

    if (node->link[0] != NULL && node->link[1] != NULL) {
        return PTREE_SUCCESS;
    }

    if (node->link[0] != NULL) {
        child = node->link[0];
    } else {
        child = node->link[1];
    }

    parent = node->parent;

    if (child != NULL) {
        child->parent = parent;
    }

    if (parent != NULL) {
        if (parent->link[0] == node) {
            parent->link[0] = child;
        } else {
            parent->link[1] = child;
        }
    } else {
        table->top = child;
    }

    clib_mem_free (node);

    if (parent && parent->lock == 0) {
        sr_table_node_unlock (parent);
    }

    return PTREE_SUCCESS;
}

/* Delete the node having a given key */
int
sr_table_node_release (struct sr_table *table, u_int8_t *key, u_int8_t keylen)
{
    struct sr_table_node *node;

    node = sr_table_node_lookup (table, key, keylen);
    if (node != NULL) {
	    sr_table_node_unlock (node);
    }

    return PTREE_SUCCESS;
}

/* Return the top node in a given prefix table */
struct sr_table_node *
sr_table_top (struct sr_table *table)
{
    struct sr_table_node *node;

    node = table->top;

    sr_table_node_lock (node);

    return node;
}

/* Return the next node */
struct sr_table_node *
sr_table_node_next (struct sr_table_node *node)
{
    struct sr_table_node *parent, *next;
    struct sr_table_node *target = NULL;

    if (node->link[0] != NULL) {
        target = node->link[0];
        goto DONE;
    }

    if (node->link[1] != NULL) {
        target = node->link[1];
        goto DONE;
    }

    next = node;
    parent = node->parent;

    while (parent != NULL) {
        if (parent->link[0] == next && parent->link[1] != NULL) {
            target = parent->link[1];
            goto DONE;
        }
        next = next->parent;
        parent = next->parent;
    }

DONE:
    sr_table_node_unlock (node);
    if (target) {
        sr_table_node_lock (target);
    }

    return target;
}

/* Return the pointer stored in a given node */
void *
sr_table_node_get_data (struct sr_table_node *node)
{
    if (node->active == PTREE_NODE_ACTIVE) {
        return node->info;
    }

    return NULL;
}

/* Store the data in a given node */
void *
sr_table_node_set_data (struct sr_table_node *node, void *data)
{
    if (node->active == PTREE_NODE_ACTIVE) {
        node->info = data;
        return data;
    }

    return NULL;
}

/* Get the key for a given node */
u8 *
sr_table_node_key (struct sr_table_node *node)
{
    return node->key;
}

/* Get the key length for a given node */
u8
sr_table_node_key_len (struct sr_table_node *node)
{
    return node->key_len;
}
