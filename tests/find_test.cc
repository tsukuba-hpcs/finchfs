#include <gtest/gtest.h>
extern "C" {
#include "../finchfsd/find.h"
#include "../lib/log.h"
}

TEST(FIND_TEST, INIT) { log_set_level("debug"); }

TEST(FIND_TEST, COMP_TEST_1)
{
	const char q[] = "name == \"*01*\"";
	find_comp_node_t *n;
	char *next;
	n = build_comp_node(q, &next);
	ASSERT_TRUE(n != NULL);
	EXPECT_EQ(n->op, FIND_COMP_EQ);
	EXPECT_EQ(n->attr, FIND_ATTR_NAME);
	EXPECT_STREQ((char *)n->value, "*01*");
}

TEST(FIND_TEST, COMP_TEST_2)
{
	const char q[] = "mtim.tv_sec < 1558682399";
	find_comp_node_t *n;
	char *next;
	n = build_comp_node(q, &next);
	ASSERT_TRUE(n != NULL);
	EXPECT_EQ(n->op, FIND_COMP_LT);
	EXPECT_EQ(n->attr, FIND_ATTR_MTIM_TVSEC);
	EXPECT_EQ(*(time_t *)n->value, 1558682399);
}

TEST(FIND_TEST, COMP_TEST_3)
{
	const char q[] = "mtim.tv_sec == 1558682399";
	find_comp_node_t *n;
	char *next;
	n = build_comp_node(q, &next);
	ASSERT_TRUE(n != NULL);
	EXPECT_EQ(n->op, FIND_COMP_EQ);
	EXPECT_EQ(n->attr, FIND_ATTR_MTIM_TVSEC);
	EXPECT_EQ(*(time_t *)n->value, 1558682399);
}

TEST(FIND_TEST, COMP_TEST_4)
{
	const char q[] = "mtim.tv_nsec == 453303489";
	find_comp_node_t *n;
	char *next;
	n = build_comp_node(q, &next);
	ASSERT_TRUE(n != NULL);
	EXPECT_EQ(n->op, FIND_COMP_EQ);
	EXPECT_EQ(n->attr, FIND_ATTR_MTIM_TVNSEC);
	EXPECT_EQ(*(int64_t *)n->value, 453303489);
}

TEST(FIND_TEST, COMP_TEST_5)
{
	const char q[] = "size == 3901";
	find_comp_node_t *n;
	char *next;
	n = build_comp_node(q, &next);
	ASSERT_TRUE(n != NULL);
	EXPECT_EQ(n->op, FIND_COMP_EQ);
	EXPECT_EQ(n->attr, FIND_ATTR_SIZE);
	EXPECT_EQ(*(uint64_t *)n->value, 3901);
}

TEST(FIND_TEST, COMP_TEST_6)
{
	const char q[] = "name==\"*01*\"";
	find_comp_node_t *n;
	char *next;
	n = build_comp_node(q, &next);
	ASSERT_TRUE(n != NULL);
	EXPECT_EQ(n->op, FIND_COMP_EQ);
	EXPECT_EQ(n->attr, FIND_ATTR_NAME);
	EXPECT_STREQ((char *)n->value, "*01*");
}

TEST(FIND_TEST, COMP_TEST_7)
{
	const char q[] = "mtim.tv_sec<1558682399";
	find_comp_node_t *n;
	char *next;
	n = build_comp_node(q, &next);
	ASSERT_TRUE(n != NULL);
	EXPECT_EQ(n->op, FIND_COMP_LT);
	EXPECT_EQ(n->attr, FIND_ATTR_MTIM_TVSEC);
	EXPECT_EQ(*(time_t *)n->value, 1558682399);
}

TEST(FIND_TEST, COMP_TEST_8)
{
	const char q[] = "mtim.tv_sec==1558682399";
	find_comp_node_t *n;
	char *next;
	n = build_comp_node(q, &next);
	ASSERT_TRUE(n != NULL);
	EXPECT_EQ(n->op, FIND_COMP_EQ);
	EXPECT_EQ(n->attr, FIND_ATTR_MTIM_TVSEC);
	EXPECT_EQ(*(time_t *)n->value, 1558682399);
}

TEST(FIND_TEST, COMP_TEST_9)
{
	const char q[] = "mtim.tv_nsec==453303489";
	find_comp_node_t *n;
	char *next;
	n = build_comp_node(q, &next);
	ASSERT_TRUE(n != NULL);
	EXPECT_EQ(n->op, FIND_COMP_EQ);
	EXPECT_EQ(n->attr, FIND_ATTR_MTIM_TVNSEC);
	EXPECT_EQ(*(int64_t *)n->value, 453303489);
}

TEST(FIND_TEST, COMP_TEST_10)
{
	const char q[] = "size==3901";
	find_comp_node_t *n;
	char *next;
	n = build_comp_node(q, &next);
	ASSERT_TRUE(n != NULL);
	EXPECT_EQ(n->op, FIND_COMP_EQ);
	EXPECT_EQ(n->attr, FIND_ATTR_SIZE);
	EXPECT_EQ(*(uint64_t *)n->value, 3901);
}

TEST(FIND_TEST, COND_TEST_1)
{
	const char q[] = "name == \"foo\" && size == 3901";
	find_condition_t *n;
	char *next = NULL;
	n = build_condition(q, &next, NULL, (find_logical_t)0);
	ASSERT_TRUE(n != NULL);
	ASSERT_TRUE(n->c == NULL);
	EXPECT_EQ(n->l->op, FIND_LOGICAL_AND);
	ASSERT_TRUE(n->l->left != NULL);
	ASSERT_TRUE(n->l->right != NULL);
	ASSERT_TRUE(n->l->left->c != NULL);
	ASSERT_TRUE(n->l->right->c != NULL);
	EXPECT_EQ(n->l->left->c->op, FIND_COMP_EQ);
	EXPECT_EQ(n->l->right->c->op, FIND_COMP_EQ);
	EXPECT_EQ(n->l->left->c->attr, FIND_ATTR_NAME);
	EXPECT_EQ(n->l->right->c->attr, FIND_ATTR_SIZE);
	EXPECT_STREQ((char *)n->l->left->c->value, "foo");
	EXPECT_EQ(*(uint64_t *)n->l->right->c->value, 3901);
}

TEST(FIND_TEST, COND_TEST_2)
{
	const char q[] = "ino == 12345 || size < 3901";
	find_condition_t *n;
	char *next = NULL;
	n = build_condition(q, &next, NULL, (find_logical_t)0);
	ASSERT_TRUE(n != NULL);
	ASSERT_TRUE(n->c == NULL);
	EXPECT_EQ(n->l->op, FIND_LOGICAL_OR);
	ASSERT_TRUE(n->l->left != NULL);
	ASSERT_TRUE(n->l->right != NULL);
	ASSERT_TRUE(n->l->left->c != NULL);
	ASSERT_TRUE(n->l->right->c != NULL);
	EXPECT_EQ(n->l->left->c->op, FIND_COMP_EQ);
	EXPECT_EQ(n->l->right->c->op, FIND_COMP_LT);
	EXPECT_EQ(n->l->left->c->attr, FIND_ATTR_INO);
	EXPECT_EQ(n->l->right->c->attr, FIND_ATTR_SIZE);
	EXPECT_EQ(*(uint64_t *)n->l->left->c->value, 12345);
	EXPECT_EQ(*(uint64_t *)n->l->right->c->value, 3901);
}

TEST(FIND_TEST, PARENTHESIS_TEST_1)
{
	const char q[] = "mtim.tv_sec < 1558682399 || (mtim.tv_sec == "
			 "1558682399 && mtim.tv_nsec < 453303489)";
	find_condition_t *n;
	char *next = NULL;
	n = build_condition(q, &next, NULL, (find_logical_t)0);
	ASSERT_TRUE(n != NULL);
	ASSERT_TRUE(n->c == NULL);
	EXPECT_EQ(n->l->op, FIND_LOGICAL_OR);
	ASSERT_TRUE(n->l->left != NULL);
	ASSERT_TRUE(n->l->right != NULL);
	ASSERT_TRUE(n->l->left->c != NULL);
	EXPECT_EQ(n->l->left->c->op, FIND_COMP_LT);
	EXPECT_EQ(n->l->left->c->attr, FIND_ATTR_MTIM_TVSEC);
	EXPECT_EQ(*(time_t *)n->l->left->c->value, 1558682399);
	ASSERT_TRUE(n->l->right->l != NULL);
	EXPECT_EQ(n->l->right->l->op, FIND_LOGICAL_AND);
	ASSERT_TRUE(n->l->right->l->left != NULL);
	ASSERT_TRUE(n->l->right->l->right != NULL);
	ASSERT_TRUE(n->l->right->l->left->c != NULL);
	ASSERT_TRUE(n->l->right->l->right->c != NULL);
	EXPECT_EQ(n->l->right->l->left->c->op, FIND_COMP_EQ);
	EXPECT_EQ(n->l->right->l->right->c->op, FIND_COMP_LT);
	EXPECT_EQ(n->l->right->l->left->c->attr, FIND_ATTR_MTIM_TVSEC);
	EXPECT_EQ(n->l->right->l->right->c->attr, FIND_ATTR_MTIM_TVNSEC);
	EXPECT_EQ(*(time_t *)n->l->right->l->left->c->value, 1558682399);
	EXPECT_EQ(*(int64_t *)n->l->right->l->right->c->value, 453303489);
}

TEST(FIND_TEST, PARENTHESIS_TEST_2)
{
	const char q[] =
	    "name == \"*01*\" && size == 3901 && (mtim.tv_sec < 1558682399 || "
	    "(mtim.tv_sec == 1558682399 && mtim.tv_nsec < 453303489))";
	find_condition_t *n;
	char *next = NULL;
	n = build_condition(q, &next, NULL, (find_logical_t)0);
	ASSERT_TRUE(n != NULL);
	ASSERT_TRUE(n->c == NULL);
	EXPECT_EQ(n->l->op, FIND_LOGICAL_AND);
	find_condition_t *ns = n->l->left;
	ASSERT_TRUE(ns != NULL);
	ASSERT_TRUE(ns->c == NULL);
	EXPECT_EQ(ns->l->op, FIND_LOGICAL_AND);
	ASSERT_TRUE(ns->l->left != NULL);
	ASSERT_TRUE(ns->l->right != NULL);
	ASSERT_TRUE(ns->l->left->c != NULL);
	ASSERT_TRUE(ns->l->right->c != NULL);
	EXPECT_EQ(ns->l->left->c->op, FIND_COMP_EQ);
	EXPECT_EQ(ns->l->right->c->op, FIND_COMP_EQ);
	EXPECT_EQ(ns->l->left->c->attr, FIND_ATTR_NAME);
	EXPECT_EQ(ns->l->right->c->attr, FIND_ATTR_SIZE);
	EXPECT_STREQ((char *)ns->l->left->c->value, "*01*");
	EXPECT_EQ(*(uint64_t *)ns->l->right->c->value, 3901);
	find_condition_t *mtim = n->l->right;
	ASSERT_TRUE(mtim != NULL);
	ASSERT_TRUE(mtim->c == NULL);
	EXPECT_EQ(mtim->l->op, FIND_LOGICAL_OR);
	ASSERT_TRUE(mtim->l->left != NULL);
	ASSERT_TRUE(mtim->l->right != NULL);
	ASSERT_TRUE(mtim->l->left->c != NULL);
	EXPECT_EQ(mtim->l->left->c->op, FIND_COMP_LT);
	EXPECT_EQ(mtim->l->left->c->attr, FIND_ATTR_MTIM_TVSEC);
	EXPECT_EQ(*(time_t *)mtim->l->left->c->value, 1558682399);
	find_condition_t *nsec = mtim->l->right;
	ASSERT_TRUE(nsec->l != NULL);
	EXPECT_EQ(nsec->l->op, FIND_LOGICAL_AND);
	ASSERT_TRUE(nsec->l->left != NULL);
	ASSERT_TRUE(nsec->l->right != NULL);
	ASSERT_TRUE(nsec->l->left->c != NULL);
	ASSERT_TRUE(nsec->l->right->c != NULL);
	EXPECT_EQ(nsec->l->left->c->op, FIND_COMP_EQ);
	EXPECT_EQ(nsec->l->right->c->op, FIND_COMP_LT);
	EXPECT_EQ(nsec->l->left->c->attr, FIND_ATTR_MTIM_TVSEC);
	EXPECT_EQ(nsec->l->right->c->attr, FIND_ATTR_MTIM_TVNSEC);
	EXPECT_EQ(*(time_t *)nsec->l->left->c->value, 1558682399);
	EXPECT_EQ(*(int64_t *)nsec->l->right->c->value, 453303489);
}

int
main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}