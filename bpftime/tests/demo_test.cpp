#include <gtest/gtest.h>


TEST(DemoTest, BasicAssertions1)
{
    EXPECT_STRNE("hello", "world");
    EXPECT_EQ(7 * 6, 42);
}
