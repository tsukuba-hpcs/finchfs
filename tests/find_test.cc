#include <gtest/gtest.h>
extern "C" {
#include "../finchfsd/find.h"
}

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

int
main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}