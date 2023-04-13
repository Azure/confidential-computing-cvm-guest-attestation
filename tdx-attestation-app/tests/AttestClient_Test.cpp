#include <gtest/gtest.h>
#include "../Utils.h"

// Demonstrate some basic assertions.
TEST(AttestClient, ShouldBeAbleToGetTdQuote)
{
  // Expect equality.
  EXPECT_EQ(7 * 6, 42);
}