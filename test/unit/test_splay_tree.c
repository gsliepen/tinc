#include "unittest.h"
#include "../../src/splay_tree.h"

typedef struct node_t {
	int id;
} node_t;

// We cannot use test_malloc / test_free here, because the library seems to be
// checking for leaks right after running each test, before doing teardown,
// which results in a bunch of spurious test failures. We rely on teardown to
// clean up after us. Valgrind and ASAN show no leaks.
static node_t *create_node(int id) {
	node_t *node = malloc(sizeof(node_t));
	node->id = id;
	return node;
}

static void free_node(node_t *node) {
	free(node);
}

static int node_compare(const node_t *lhs, const node_t *rhs) {
	return lhs->id - rhs->id;
}

static int test_setup(void **state) {
	splay_tree_t *tree = splay_alloc_tree((splay_compare_t) node_compare, (splay_action_t) free_node);

	if(!tree) {
		return -1;
	}

	*state = tree;
	return 0;
}

static int test_teardown(void **state) {
	splay_delete_tree(*state);
	return 0;
}

static void test_tree_allocation_deletion(void **state) {
	(void)state;

	splay_tree_t *tree = splay_alloc_tree((splay_compare_t) node_compare,
	                                      (splay_action_t) free_node);
	assert_non_null(tree);

	node_t *one = create_node(1);
	assert_non_null(splay_insert(tree, one));

	node_t *two = create_node(2);
	assert_non_null(splay_insert(tree, two));

	// AddressSanitizer will notify us if there's a leak
	splay_delete_tree(tree);
}

static int multiply_tree_node_calls = 0;

static void increment_id_tree_node(node_t *node) {
	++node->id;
	++multiply_tree_node_calls;
}

static int multiply_splay_node_calls = 0;

static void multiply_id_splay_node(splay_node_t *node) {
	node_t *t = node->data;
	t->id *= 2;
	++multiply_splay_node_calls;
}

static void test_splay_foreach(void **state) {
	splay_tree_t *tree = *state;

	node_t *one = create_node(1);
	splay_node_t *node_one = splay_insert(tree, one);
	assert_ptr_equal(one, node_one->data);

	node_t *two = create_node(5);
	splay_node_t *node_two = splay_insert(tree, two);
	assert_ptr_equal(two, node_two->data);

	splay_foreach(tree, (splay_action_t) increment_id_tree_node);
	assert_int_equal(2, one->id);
	assert_int_equal(6, two->id);

	splay_foreach_node(tree, (splay_action_t) multiply_id_splay_node);
	assert_int_equal(4, one->id);
	assert_int_equal(12, two->id);

	assert_int_equal(2, multiply_tree_node_calls);
	assert_int_equal(2, multiply_splay_node_calls);
}

static void test_splay_each(void **state) {
	splay_tree_t *tree = *state;

	node_t *one = create_node(1);
	node_t *two = create_node(2);

	splay_insert(tree, one);
	splay_insert(tree, two);

	// splay_each should iterate over all nodes
	for splay_each(node_t, n, tree) {
		n->id = -n->id;
	}

	assert_int_equal(-1, one->id);
	assert_int_equal(-2, two->id);

	// splay_each should allow removal of the current node
	for splay_each(node_t, n, tree) {
		splay_delete(tree, n);
	}
}

static void test_splay_basic_ops(void **state) {
	splay_tree_t *tree = *state;
	node_t *node = create_node(1);

	// Should not find anything if the tree is empty
	node_t *found_one = splay_search(tree, node);
	assert_null(found_one);

	// Insertion should return a non-NULL node with `data` pointing to our `tree_node`
	splay_node_t *node_one = splay_insert(tree, node);
	assert_ptr_equal(node, node_one->data);

	// Should find after insertion
	found_one = splay_search(tree, node);
	assert_ptr_equal(node, found_one);
}

static void test_splay_insert_before_after(void **state) {
	splay_tree_t *tree = *state;

	node_t *one = create_node(1);
	splay_node_t *node_one = splay_insert(tree, one);
	assert_non_null(node_one);

	// splay_insert_before should set up `prev` and `next` pointers
	splay_node_t *node_two = splay_alloc_node();
	assert_non_null(node_two);
	node_two->data = create_node(2);

	splay_insert_after(tree, node_one, node_two);
	assert_null(node_one->prev);
	assert_ptr_equal(node_one->next, node_two);
	assert_ptr_equal(node_two->prev, node_one);
	assert_null(node_two->next);

	splay_node_t *node_thr = splay_alloc_node();
	assert_non_null(node_thr);
	node_thr->data = create_node(3);

	splay_insert_after(tree, node_two, node_thr);
	assert_null(node_one->prev);
	assert_ptr_equal(node_one->next, node_two);
	assert_ptr_equal(node_two->prev, node_one);
	assert_ptr_equal(node_two->next, node_thr);
	assert_ptr_equal(node_thr->prev, node_two);
	assert_null(node_thr->next);
}

static void test_search_node(void **state) {
	splay_tree_t *tree = *state;

	node_t *one = create_node(1);
	node_t *two = create_node(2);

	splay_node_t *one_node = splay_search_node(tree, one);
	assert_null(one_node);

	one_node = splay_insert(tree, one);
	assert_ptr_equal(one_node, splay_search_node(tree, one));

	splay_node_t *two_node = splay_search_node(tree, two);
	assert_null(two_node);

	two_node = splay_insert(tree, two);
	assert_ptr_equal(one_node, splay_search_node(tree, one));
	assert_ptr_equal(two_node, splay_search_node(tree, two));

	node_t *copy_one = create_node(1);
	node_t *copy_two = create_node(2);

	splay_delete(tree, one);
	assert_null(splay_search_node(tree, copy_one));
	assert_ptr_equal(two_node, splay_search_node(tree, two));

	splay_delete(tree, two);
	assert_null(splay_search_node(tree, copy_one));
	assert_null(splay_search_node(tree, copy_two));

	free_node(copy_one);
	free_node(copy_two);
}

static void test_unlink(void **state) {
	splay_tree_t *tree = *state;
	node_t *one = create_node(1);

	splay_node_t *node_one = splay_insert(tree, one);

	// Unlink should return the unlinked node
	splay_node_t *unlinked_one = splay_unlink(tree, one);
	assert_ptr_equal(one, unlinked_one->data);

	// Unlinking the same node should return NULL
	assert_null(splay_unlink(tree, one));

	// Inserting it back should return the same node
	unlinked_one = splay_insert_node(tree, unlinked_one);
	assert_ptr_equal(node_one, unlinked_one);
}

static void test_unlink_node(void **state) {
	splay_tree_t *tree = *state;
	node_t *one = create_node(1);

	splay_node_t *node_one = splay_insert(tree, one);
	assert_ptr_equal(one, node_one->data);
	assert_ptr_equal(one, splay_search(tree, one));
	assert_ptr_equal(node_one, splay_search_node(tree, one));

	splay_unlink_node(tree, node_one);
	assert_null(splay_search(tree, one));
	assert_null(splay_search_node(tree, one));

	splay_free_node(tree, node_one);
}

static void test_delete_node(void **state) {
	splay_tree_t *tree = *state;
	node_t *one = create_node(1);

	splay_node_t *node_one = splay_insert(tree, one);
	assert_ptr_equal(one, node_one->data);
	assert_ptr_equal(one, splay_search(tree, one));
	assert_ptr_equal(node_one, splay_search_node(tree, one));

	node_t *copy = create_node(1);
	assert_ptr_equal(one, splay_search(tree, copy));

	splay_delete_node(tree, node_one);
	assert_null(splay_search(tree, copy));

	free_node(copy);
}

#define test_with_state(test_func) \
	cmocka_unit_test_setup_teardown((test_func), test_setup, test_teardown)

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_tree_allocation_deletion),
		test_with_state(test_splay_basic_ops),
		test_with_state(test_splay_insert_before_after),
		test_with_state(test_splay_foreach),
		test_with_state(test_splay_each),
		test_with_state(test_search_node),
		test_with_state(test_unlink),
		test_with_state(test_unlink_node),
		test_with_state(test_delete_node),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
