#if defined(USE_PAGE_HASH)

#include "merkle.h"

#include <assert.h>
#include <malloc.h>
#include <string.h>

#include "slice.h"
#include "paging.h"
#include "sha256.h"
#include "vm_defs.h"

#ifndef MERK_SILENT
#define MERK_LOG printf
#else
#define MERK_LOG(...)
#endif

_Static_assert(sizeof(merkle_node_t) == 4096, "merkle_node_t is not 4096 bytes!");

static merkle_node_t*
merk_alloc_page(void) {
  void* page               = (void*)paging_alloc_backing_page();
  merkle_node_t* free_node = (merkle_node_t*)page;
  memset(free_node, 0, sizeof(*free_node));
  return free_node;
}

static merkle_node_t* merk_free_list = NULL;

static merkle_node_t*
merk_alloc_node(void) {
  if (!merk_free_list)
    merk_free_list = merk_alloc_page();

  merkle_node_t* out = merk_free_list;
  merk_free_list = merk_free_list->free_list_next;
  out->free_list_next = NULL;
  memset(out, 0, sizeof *out);
  return out;
}

static void
merk_free_node(merkle_node_t* node) {
  assert(!node->free_list_next);
  node->free_list_next = merk_free_list;
  merk_free_list = node;
}

void
merk_clear(merkle_node_t* root) {
  for (int i = 0; i < NODE_CHILDREN; i++) {
    merk_clear(root->children[i]);
    merk_free_node(root->children[i]);
    root->children[i] = NULL;
  }
}

typedef struct {
  uintptr_t key;
  merk_hash_t val_hash;
} merk_item_t;

struct percolate {
  bool any;
  union {
    struct {};
    struct {
      merk_item_t item;
      merkle_node_t *right_node;
    };
  };
};

/** Return the position of the given `key` in `node`, or the position to insert it in */
static size_t
merk_key_search(const merkle_node_t *node, uintptr_t key) {
  // TODO: binary search? measure impact
  size_t i;
  for (i = 0; i < NODE_ITEMS && node->keys[i] && key > node->keys[i]; i++);
  return i;
}

/** Return the number of contiguous nonzero keys in `node` */
static size_t
merk_nonzero_keys(const merkle_node_t *node) {
  size_t i;
  for (i = 0; i < NODE_ITEMS && node->keys[i]; i++);
  return i;
}

bool
merk_is_nonleaf(const merkle_node_t *node) {
  for (size_t i = 0; i < NODE_CHILDREN; i++)
    if (node->children[i])
      return true;
  return false;
}

static merk_hash_t merk_calc_hash(merkle_node_t *node) {
  SHA256_CTX sha;
  merk_hash_t out;
  if (!node) {
    memset(&out, 0, sizeof out);
    return out;
  }
  sha256_init(&sha);
  sha256_update(&sha, (uint8_t *)node, sizeof(*node));
  sha256_final(&sha, out.val);
  return out;
}

static struct percolate
merk_insert_into(merkle_node_t *node, struct percolate ins) {
  int num_vals = merk_nonzero_keys(node);
  if (num_vals < NODE_ITEMS) {
    int i = merk_key_search(node, ins.item.key);
    
    // printf("starting with "); _print_node_id(node); printf(" with children "); _print_children(node); printf("\n");
    // printf("inserting %zu with right ", ins.item.key); if (ins.right_node) _print_node_id(ins.right_node); else printf("()"); printf("\n");

    slice_move(&node->keys[i+1],         SLICE(node->keys,         i,     NODE_ITEMS - 1));
    slice_move(&node->val_hashes[i+1],   SLICE(node->val_hashes,   i,     NODE_ITEMS - 1));
    slice_move(&node->children[i+2],     SLICE(node->children,     i + 1, NODE_CHILDREN - 1));
    slice_move(&node->child_hashes[i+2], SLICE(node->child_hashes, i + 1, NODE_CHILDREN - 1));
    node->keys[i] = ins.item.key;
    node->val_hashes[i] = ins.item.val_hash;
    node->children[i+1] = ins.right_node;
    node->child_hashes[i] = merk_calc_hash(node->children[i]);
    node->child_hashes[i+1] = merk_calc_hash(ins.right_node);
    
    // printf("now "); _print_node_id(node); printf(" with children "); _print_children(node); printf("\n");
    
    return (struct percolate) { .any=false };
      
  } else {
    // printf("split "); _print_node_id(node); printf(" while inserting %zu\n", ins.item.key);

    // no room in this node, need to split
    merk_item_t median = { .key = node->keys[NODE_MEDIAN], .val_hash = node->val_hashes[NODE_MEDIAN] };
    merkle_node_t *new_right = merk_alloc_node();
    
    slice_copy(new_right->keys,       SLICE(node->keys,       NODE_MEDIAN+1, NODE_ITEMS));
    slice_copy(new_right->val_hashes, SLICE(node->val_hashes, NODE_MEDIAN+1, NODE_ITEMS));
    slice_fill(SLICE(node->keys,       NODE_MEDIAN, NODE_ITEMS), 0);
    slice_fill(SLICE(node->val_hashes, NODE_MEDIAN, NODE_ITEMS), 0);

    slice_copy(new_right->children,     SLICE(node->children,     NODE_CHILDREN/2, NODE_CHILDREN));
    slice_copy(new_right->child_hashes, SLICE(node->child_hashes, NODE_CHILDREN/2, NODE_CHILDREN));
    slice_fill(SLICE(node->children,     NODE_CHILDREN/2, NODE_CHILDREN), 0);
    slice_fill(SLICE(node->child_hashes, NODE_CHILDREN/2, NODE_CHILDREN), 0);

    merkle_node_t *either_node[2] = {node, new_right};
    merk_insert_into(either_node[ins.item.key > median.key], ins);
    
    // printf("... into "); _print_node_id(node); printf(", "); _print_node_id(new_right); printf("\n");
    // printf("left "); _print_node_id(node); printf(" with children "); _print_children(node); printf("\n");
    
    // printf("new_left has hashes:\n");
    // for (int i = 0; i < NODE_CHILDREN; i++) {
    //   printf("  %d: %lx\n", i, *(uint64_t*)node->child_hashes[i].val);
    // }

    // printf("new_right has hashes:\n");
    // for (int i = 0; i < NODE_CHILDREN; i++) {
    //   printf("  %d: %lx\n", i, *(uint64_t*)new_right->child_hashes[i].val);
    // }

    return (struct percolate) { .any=true, .item=median, .right_node=new_right };
  }
}

static struct percolate
merk_insert_inner(merkle_node_t *node, struct percolate ins) {
  // printf("insert %zu into ", ins.item.key); _print_node_id(node); printf("\n");
  int i = merk_key_search(node, ins.item.key);

  if (node->keys[i] == ins.item.key) {
    // Overwriting a preexisting key
    assert(!ins.right_node);
    node->keys[i] = ins.item.key;
    node->val_hashes[i] = ins.item.val_hash;
    return (struct percolate) { .any=false };
  }

  if (merk_is_nonleaf(node)) {
    // Not a leaf node, need to recurse
    assert(node->children[i]);

    ins = merk_insert_inner(node->children[i], ins);
    node->child_hashes[i] = merk_calc_hash(node->children[i]);
    if (!ins.any)
      return ins;
  }

  return merk_insert_into(node, ins);
}
            
            
int
merk_insert(merkle_tree_t *tree, uintptr_t key, const merk_hash_t *hash) {
  merk_item_t item = { .key=key, .val_hash=*hash };
  struct percolate ins = { .any=true, .item=item, .right_node=NULL };

  if (!tree->root)
    tree->root = merk_alloc_node();

  ins = merk_insert_inner(tree->root, ins);
  if (ins.any) {
    merkle_node_t *old_root = tree->root;
    tree->root = merk_alloc_node();
    *tree->root = (merkle_node_t) {
      .keys         = { ins.item.key },
      .val_hashes   = { ins.item.val_hash },
      .children     = { old_root, ins.right_node },
      .child_hashes = { merk_calc_hash(old_root), merk_calc_hash(ins.right_node) },
    };
    tree->root_hash = merk_calc_hash(tree->root);
  }
  return 0;
}


bool
merk_verify(merkle_node_t *node, uintptr_t key, const uint8_t _hash[32]) {
  merk_hash_t *hash = (merk_hash_t *)_hash;
  merkle_node_t next_node;

  while (true) {
    size_t i = merk_key_search(node, key);
    if (node->keys[i] == key) {
      // Found the key, compare the given hash
      if (!!memcmp(&node->val_hashes[i], hash, sizeof *hash)) {
        fprintf(stderr, "Could not find Merkle tree entry with key=%zx matching the hash!\n", key);
        return false;
      }
      return true;
    }

    // printf("Checking children ");
    // _print_children(node);
    // printf(" for key %zx\n", key);
    merkle_node_t *next_node_ptr = node->children[i];
    if (!next_node_ptr) {
      // Couldn't find the key
      fprintf(stderr, "Could not find Merkle tree entry with key=%zx!\n", key);
      return false;
    }

    merk_hash_t expected_hash = node->child_hashes[i];

    next_node = *(volatile merkle_node_t *)next_node_ptr;
    // printf("Traversing node "); _print_node_id(node); printf(" -> node "); _print_node_id(&next_node); printf("!\n");
    node = &next_node;

    merk_hash_t found_hash = merk_calc_hash(node);
    if (!!memcmp(&found_hash, &expected_hash, sizeof found_hash)) {
      // Something corrupted this node's data; fail
      fprintf(stderr, "Merkle tree hash corrupted while querying key=%zx!\n", key);
      printf("Expected %lx, found %lx", *(uint64_t *)expected_hash.val, *(uint64_t *)found_hash.val);
      printf(" in node "); _print_node_id(node); printf("!\n");
      return false;
    }
  }
}

    
void _print_node_id(merkle_node_t *node) {
  printf("[ ");
  for (int i = 0; i < NODE_ITEMS; i++) {
    if (node->keys[i])
      printf("%zx ", node->keys[i]);
  }
  printf("] ");
  printf("%x", node);
}

void _print_node_hash(merkle_node_t *node) {
  printf("%016lx", *(uint64_t *)merk_calc_hash(node).val);
}

void _print_node_ptr_or_null(merkle_node_t *node) {
  if (node)
    printf("%x", node);
  else
    printf("()");
}

void _print_children(merkle_node_t *node) {
  printf("[ ");
  _print_node_ptr_or_null(node->children[0]);
  for (int i = 1; i < NODE_CHILDREN; i++) {
    printf(", ");
    _print_node_ptr_or_null(node->children[i]);
  }
  printf(" ]");
}

void _print_edges(merkle_node_t *node, const char *type) {
  void (*node_printer)(merkle_node_t *);

  if (!strcmp(type, "hashes")) {
    node_printer = _print_node_hash;
  } else {
    node_printer = _print_node_id;
  }

  if (node->children[0]) {
    printf("\"");
    node_printer(node);
    printf("\" -- \"");
    node_printer(node->children[0]);
    printf("\" [label=\"x<%zx\"];\n", node->keys[0]);

    _print_edges(node->children[0], type);
  }

  for (int i = 1; i < NODE_CHILDREN; i++) {
    if (node->children[i]) {
      printf("\"");
      node_printer(node);
      printf("\" -- \"");
      node_printer(node->children[i]);

      printf("\" [label=\"%zx<x", node->keys[i-1]);
      if (i != NODE_ITEMS && node->keys[i])
        printf("<%zx", node->keys[i]);
      printf("\"];\n");
      
      _print_edges(node->children[i], type);
    }
  }
}

void _print_graph(merkle_node_t *root, const char *type) {
  printf("strict graph {\n");
  _print_edges(root, type);
  printf("}\n");
}

#endif
