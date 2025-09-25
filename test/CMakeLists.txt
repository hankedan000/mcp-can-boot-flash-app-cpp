find_package(cppunit REQUIRED)

add_executable(ExampleTest ExampleTest.cpp)
add_test(NAME ExampleTest COMMAND ExampleTest)
target_link_libraries(ExampleTest PUBLIC
	${CPPUNIT_LIBRARIES})
