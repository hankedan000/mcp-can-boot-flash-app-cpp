add_executable(flash-app
	flash-app.cpp)
target_link_libraries(flash-app
	cpptqdm)

install(TARGETS flash-app)
