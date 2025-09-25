#include "ExampleTest.h"

#include <cppunit/ui/text/TestRunner.h>

ExampleTest::ExampleTest()
{
}

void
ExampleTest::setUp()
{
	// run before each test case
}

void
ExampleTest::tearDown()
{
	// run after each test case
}

void
ExampleTest::test1()
{
	// test some stuff...
}

int main()
{
	CppUnit::TextTestRunner runner;
	runner.addTest(ExampleTest::suite());
	return runner.run() ? EXIT_SUCCESS : EXIT_FAILURE;
}
