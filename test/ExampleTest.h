#pragma once

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

class ExampleTest : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(ExampleTest);
	CPPUNIT_TEST(test1);
	CPPUNIT_TEST_SUITE_END();

public:
	ExampleTest();
	void setUp();
	void tearDown();

protected:
	void test1();

private:

};
