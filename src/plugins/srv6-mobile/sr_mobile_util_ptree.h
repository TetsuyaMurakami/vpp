/*
 * sr_mbile_util_ptree.h
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

#ifndef _PTREE_H_
#define _PTREE_H_
typedef int (*ptree_del_cb_t) (void *info);

/* Error code */
#define PTREE_SUCCESS		0
#define PTREE_FAILURE		-1
#define PTREE_DELETE_FAILURE	-2

struct ptree_node {
    struct ptree_node 	*link[2];
#define left_child  link[0]
#define right_child link[1]

    struct ptree 	    *tree;
    struct ptree_node 	*parent;

    void		        *info;

    _Atomic u32         lock;

    u8		            active;
#define PTREE_NODE_INACTIVE	0
#define PTREE_NODE_ACTIVE	1

    u8      		    padding[2];

    u8      		    key_len;
    u8      		    key[0];
};

struct ptree {
    struct ptree_node 	*top;
    u8      		    family;
    u8      		    max_key_len;
    u8      		    max_key_siz;

    ptree_del_cb_t	    delete_cb;
};

struct ptree * ptree_new (u8 family, u8 max_keylen, ptree_del_cb_t del);
int ptree_delete (struct ptree *tree, int force);

void ptree_node_lock (struct ptree_node *node);
int ptree_node_unlock (struct ptree_node *node);

struct ptree_node *ptree_node_new (struct ptree *tree, u8 *key, u8 keylen);
struct ptree_node *ptree_node_get (struct ptree *tree, u8 *key, u8 keylen);

struct ptree_node *ptree_node_lookup (struct ptree *tree, u8 *key, u8 keylen);
struct ptree_node *ptree_node_match (struct ptree *tree, u8 *key, u8 keylen);

int ptree_node_delete (struct ptree *tree, struct ptree_node *node);
int ptree_node_release (struct ptree *tree, u8 *key, u8 keylen);

struct ptree_node *ptree_top (struct ptree *tree);
struct ptree_node *ptree_node_next (struct ptree_node *node);

void *ptree_node_get_data (struct ptree_node *node);
void *ptree_node_set_data (struct ptree_node *node, void *data);

u_int8_t *ptree_node_key (struct ptree_node *node);
u_int8_t ptree_node_key_len (struct ptree_node *node);

#endif /* _PTREE_H_ */
