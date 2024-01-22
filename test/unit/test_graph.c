#include "unittest.h"
#include "../../src/connection.h"
#include "../../src/node.h"
#include "../../src/xalloc.h"

extern void sssp_bfs(void);

static void connect_nodes(node_t *from, node_t *to, int weight) {
	edge_t *direct = new_edge();
	direct->from = from;
	direct->to = to;
	direct->weight = weight;
	edge_add(direct);

	edge_t *reverse = new_edge();
	reverse->from = to;
	reverse->to = from;
	reverse->weight = weight;
	edge_add(reverse);
}

static node_t *make_node(const char *name) {
	node_t *node = new_node(name);
	node->status.reachable = true;
	node_add(node);
	return node;
}

static void test_sssp_bfs_2(void **state) {
	(void)state;

	node_t *mars = make_node("mars");
	node_t *saturn = make_node("saturn");
	node_t *neptune = make_node("neptune");

	//          1000            500
	// myself ---------- mars ------------- neptune
	//      \                              /
	//       ------- saturn --------------
	//          50               501

	// Upper route
	connect_nodes(myself, mars, 1000);
	connect_nodes(mars, neptune, 500);

	// Lower route
	connect_nodes(myself, saturn, 50);
	connect_nodes(saturn, neptune, 501);

	sssp_bfs();

	assert_true(mars->status.visited);
	assert_true(saturn->status.visited);
	assert_true(neptune->status.visited);

	assert_false(mars->status.indirect);
	assert_false(saturn->status.indirect);
	assert_false(neptune->status.indirect);

	assert_int_equal(1, mars->distance);
	assert_int_equal(1, saturn->distance);
	assert_int_equal(2, neptune->distance);

	assert_ptr_equal(mars, mars->nexthop);
	assert_ptr_equal(saturn, saturn->nexthop);
	assert_ptr_equal(saturn, neptune->nexthop);

	assert_ptr_equal(lookup_edge(myself, mars), mars->prevedge);
	assert_ptr_equal(lookup_edge(myself, saturn), saturn->prevedge);
	assert_ptr_equal(lookup_edge(saturn, neptune), neptune->prevedge);

	assert_ptr_equal(mars, mars->via);
	assert_ptr_equal(saturn, saturn->via);
	assert_ptr_equal(neptune, neptune->via);
}

static void test_sssp_bfs(void **state) {
	(void)state;

	node_t *mars = make_node("mars");
	node_t *saturn = make_node("saturn");
	node_t *neptune = make_node("neptune");

	//          50            1000
	// myself ------ mars ------------- neptune
	//      \                             /
	//       ----------------- saturn ----
	//              500                10

	// Upper route
	connect_nodes(myself, mars, 50);
	connect_nodes(mars, neptune, 1000);

	// Lower route
	connect_nodes(myself, saturn, 500);
	connect_nodes(saturn, neptune, 10);

	sssp_bfs();

	assert_true(mars->status.visited);
	assert_true(saturn->status.visited);
	assert_true(neptune->status.visited);

	assert_false(mars->status.indirect);
	assert_false(saturn->status.indirect);
	assert_false(neptune->status.indirect);

	assert_int_equal(1, mars->distance);
	assert_int_equal(1, saturn->distance);
	assert_int_equal(2, neptune->distance);

	assert_ptr_equal(mars, mars->nexthop);
	assert_ptr_equal(saturn, saturn->nexthop);
	assert_ptr_equal(saturn, neptune->nexthop);

	assert_ptr_equal(lookup_edge(myself, mars), mars->prevedge);
	assert_ptr_equal(lookup_edge(myself, saturn), saturn->prevedge);
	assert_ptr_equal(lookup_edge(saturn, neptune), neptune->prevedge);

	assert_ptr_equal(mars, mars->via);
	assert_ptr_equal(saturn, saturn->via);
	assert_ptr_equal(neptune, neptune->via);
}

static int setup(void **state) {
	(void)state;
	myself = new_node("myself");
	return 0;
}

static int teardown(void **state) {
	(void)state;
	free_node(myself);
	exit_nodes();
	exit_edges();
	return 0;
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_sssp_bfs, setup, teardown),
		cmocka_unit_test_setup_teardown(test_sssp_bfs_2, setup, teardown)
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
