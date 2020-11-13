#pragma once

#if defined(USE_FREEMEM) && defined(USE_PAGING)

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define b2(x)   (   (x) | (   (x) >> 1) )
#define b4(x)   ( b2(x) | ( b2(x) >> 2) )
#define b8(x)   ( b4(x) | ( b4(x) >> 4) )
#define b16(x)  ( b8(x) | ( b8(x) >> 8) )  
#define b32(x)  (b16(x) | (b16(x) >>16) )
#define next_power_of_2(x)      (b32(x-1) + 1)

typedef struct {
  uint8_t val[32];
} merk_hash_t;

#define NODE_CHILDREN 32
#define NODE_ITEMS (NODE_CHILDREN-1)
#define NODE_MEDIAN (NODE_ITEMS / 2)
#define MERK_NODE_SIZE next_power_of_2(32 * 2 * (NODE_ITEMS + NODE_CHILDREN))

typedef union merkle_node {
  struct {
    uintptr_t keys[NODE_ITEMS];
    merk_hash_t val_hashes[NODE_ITEMS];

    merk_hash_t child_hashes[NODE_CHILDREN];
    union merkle_node* children[NODE_CHILDREN];

    union merkle_node *free_list_next;
  };
  struct {
    uint64_t raw_words[MERK_NODE_SIZE / 8];
  };
} merkle_node_t;

typedef struct {
  merkle_node_t *root;
  merk_hash_t root_hash;
} merkle_tree_t;

int
merk_insert(merkle_tree_t* root, uintptr_t key, const merk_hash_t *hash);
bool
merk_verify(
    merkle_tree_t* root, uintptr_t key, const uint8_t hash[32]);
void
merk_clear(merkle_node_t* root);
bool
merk_is_nonleaf(const merkle_node_t *node);

void _print_graph(merkle_node_t *root, const char *type);
void _print_node_id(merkle_node_t *node);
void _print_children(merkle_node_t *node);

#endif
