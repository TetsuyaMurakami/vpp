/*
 * sr_mbile_util_ptree.c
 *
 * Copyright (c) 2023 Arrcus Inc and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <vnet/vnet.h>

#include "sr_mobile_util_ptree.h"

static const u_int8_t mask_bit[] = {
    0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff
};

/* Create a new prefix tree */
struct ptree *
ptree_new (u_int8_t family, u_int8_t max_keylen, ptree_del_cb_t del)
{
    struct ptree *tree;

    tree = clib_mem_alloc (sizeof (struct ptree));
    if (! tree) {
        return NULL;
    }

    tree->family = family; tree->max_key_len = max_keylen;

    tree->max_key_siz = (max_keylen >> 3);
    if ((max_keylen & 0x7) != 0) {
        tree->max_key_siz++;
    }

    tree->delete_cb = del;

    return tree;
}

/* Destroy the prefix tree */
int
ptree_delete (struct ptree *tree, int force)
{
    struct ptree_node *node, *next;

    if (force == 0) {
        if (tree->top != NULL) {
            return PTREE_DELETE_FAILURE;
        }
    } else {
        for (node = ptree_top(tree); node != NULL; node = next) {
            next = ptree_node_next (node);
	        node->lock = 0;
            ptree_node_unlock (node);
        }
    }

    clib_mem_free (tree);
    return PTREE_SUCCESS;
}

/* Lock the node in a given prefix tree */
void
ptree_node_lock (struct ptree_node *node)
{
    clib_atomic_fetch_add (&node->lock, 1);
}

/* Unlock the node in a given prefix tree and then delete the node if the lock is 0 */
int
ptree_node_unlock (struct ptree_node *node)
{
    struct ptree *tree;

    if (node->lock != 0)
        clib_atomic_fetch_sub (&node->lock, 1);

    if (node->lock == 0) {
        tree = node->tree;

        if (tree->delete_cb && node->info) {
            tree->delete_cb (node->info);
            node->info = NULL;
        }

        ptree_node_delete (tree, node);
        return 1;
    }

    return 0;
}

/* Crate a new node in a given prefix tree */
struct ptree_node *
ptree_node_new (struct ptree *tree, u_int8_t *key, u_int8_t keylen)
{
    size_t size;
    struct ptree_node *node;

    size = sizeof (struct ptree_node) + tree->max_key_siz; 

    node = clib_mem_alloc (size);
    if (! node) {
        return NULL;
    }

    node->key_len = keylen;
    memcpy (node->key, key, tree->max_key_siz);

    node->tree = tree;

    return node;
}

/* Create a new node in a given prefix tree with the intermidiate node */
struct ptree_node *
ptree_node_base (struct ptree *tree, struct ptree_node *node, u_int8_t *key, u_int8_t keylen)
{
    int i, j;
    int boundary = 0;
    u_int8_t len;
    u_int8_t diff;
    u_int8_t mask = 0x80;
    size_t size;
    struct ptree_node *new;

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

    size = sizeof (struct ptree_node) + tree->max_key_siz;

    new = clib_mem_alloc (size);
    if (! new) {
        return NULL;
    }

    new->tree = tree;

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
ptree_node_key_match (u_int8_t *k1, u_int8_t k1len, u_int8_t *k2, u_int8_t k2len)
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
ptree_node_check_bit (u_int8_t *key, u_int8_t keylen)
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
ptree_node_set_link (struct ptree_node *n1, struct ptree_node *n2)
{
    int bit;

    bit = ptree_node_check_bit (n2->key, n1->key_len);

    n1->link[bit] = n2;
    n2->parent = n1;
}

/* Get the node in a given prefix tree. If not present, a new node is created */
struct ptree_node *
ptree_node_get (struct ptree *tree, u_int8_t *key, u_int8_t keylen)
{
    struct ptree_node *match = NULL;
    struct ptree_node *node;
    struct ptree_node *new;
    struct ptree_node *n;

    if (keylen > tree->max_key_len) {
        return NULL;
    }

    node = tree->top;
    while (node != NULL && node->key_len <= keylen) {
        if (ptree_node_key_match (node->key, node->key_len, key, keylen)) {
            if (node->key_len == keylen) {
                if (node->active != PTREE_NODE_ACTIVE) {
                     node->active = PTREE_NODE_ACTIVE;
                }
                ptree_node_lock (node);
                return node;
            } else {
                match = node;
                node = node->link[ptree_node_check_bit(key, node->key_len)];
            }
        } else {
            break;
        }
    }

    if (node == NULL) {
        new = ptree_node_new (tree, key, keylen);
        if (! new) {
            return NULL;
        }

        if (match != NULL) {
            ptree_node_set_link (match, new);
        } else {
            tree->top = new;
        }
    } else {
        new = ptree_node_base (tree, node, key, keylen);
        if (! new) {
            return NULL;
        }

        ptree_node_set_link (new, node);

        if (match != NULL) {
            ptree_node_set_link (match, new);
        } else {
            tree->top = new;
        }

        if (new->key_len != keylen) {
          n = ptree_node_new (tree, key, keylen);
          ptree_node_set_link (new, n);
          new = n;
        }
    }

    ptree_node_lock (new);

    new->active = PTREE_NODE_ACTIVE;

    return new;
}

/* Exact match */
struct ptree_node *
ptree_node_lookup (struct ptree *tree, u_int8_t *key, u_int8_t keylen)
{
    struct ptree_node *node;

    if (keylen > tree->max_key_len) {
        return NULL;
    }

    node = tree->top;
    while (node != NULL && node->key_len <= keylen) {
        if (ptree_node_key_match (node->key, node->key_len, key, keylen)) {
            if (node->key_len == keylen) {
                if (node->active == PTREE_NODE_ACTIVE) {
                    ptree_node_lock(node);
                    return node;
                } else {
                    return NULL;
                }
            } else {
                node = node->link[ptree_node_check_bit(key, node->key_len)];
            }
        } else {
            break;
        }
    }

    return NULL;
}

/* Longest match */
struct ptree_node *
ptree_node_match (struct ptree *tree, u_int8_t *key, u_int8_t keylen)
{
    struct ptree_node *node;
    struct ptree_node *match = NULL;
    
    if (keylen > tree->max_key_len) {
        return NULL;
    }
    
    node = tree->top;
    while (node != NULL && node->key_len <= keylen) {
        if (ptree_node_key_match (node->key, node->key_len, key, keylen)) {
            match = node;
            node = node->link[ptree_node_check_bit(key, node->key_len)];
        } else {
            break;
        }
    }

    if ((match == NULL) || (match->active != PTREE_NODE_ACTIVE)) {
        return NULL;
    }

    ptree_node_lock (match);
    return match;
}

/* Delete the node in a given prefix tree */
int
ptree_node_delete (struct ptree *tree, struct ptree_node *node)
{
    struct ptree_node *parent;
    struct ptree_node *child;

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
        tree->top = child;
    }

    clib_mem_free (node);

    if (parent && parent->lock == 0) {
        ptree_node_unlock (parent);
    }

    return PTREE_SUCCESS;
}

/* Delete the node having a given key */
int
ptree_node_release (struct ptree *tree, u_int8_t *key, u_int8_t keylen)
{
    struct ptree_node *node;

    node = ptree_node_lookup (tree, key, keylen);
    if (node != NULL) {
	    ptree_node_unlock (node);
    }

    return PTREE_SUCCESS;
}

/* Return the top node in a given prefix tree */
struct ptree_node *
ptree_top (struct ptree *tree)
{
    struct ptree_node *node;

    node = tree->top;

    ptree_node_lock (node);

    return node;
}

/* Return the next node */
struct ptree_node *
ptree_node_next (struct ptree_node *node)
{
    struct ptree_node *parent, *next;
    struct ptree_node *target = NULL;

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
    ptree_node_unlock (node);
    if (target) {
        ptree_node_lock (target);
    }

    return target;
}

/* Return the pointer stored in a given node */
void *
ptree_node_get_data (struct ptree_node *node)
{
    if (node->active == PTREE_NODE_ACTIVE) {
        return node->info;
    }

    return NULL;
}

/* Store the data in a given node */
void *
ptree_node_set_data (struct ptree_node *node, void *data)
{
    if (node->active == PTREE_NODE_ACTIVE) {
        node->info = data;
        return data;
    }

    return NULL;
}

/* Get the key for a given node */
u8 *
ptree_node_key (struct ptree_node *node)
{
    return node->key;
}

/* Get the key length for a given node */
u8
ptree_node_key_len (struct ptree_node *node)
{
    return node->key_len;
}
