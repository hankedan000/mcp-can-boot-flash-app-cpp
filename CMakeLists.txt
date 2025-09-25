cmake_minimum_required (VERSION 3.1)

project(TemplateProject VERSION 1.0.0)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON) # used by SonarQube in IDE

option(TEMPLATE_PROJECT_BUILD_ALL "Build all artifacts" OFF)

# testing options
option(TEMPLATE_PROJECT_BUILD_TESTS "Build tests" ON)

# add project's module directory to CMAKE_MODULE_PATH
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# update all submodules
find_package(Git QUIET)
if(GIT_FOUND AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
	# Update submodules as needed
	option(GIT_SUBMODULE "Check submodules during build" ON)
	if(GIT_SUBMODULE)
		message(STATUS "Submodule update")
		execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
						WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
						RESULT_VARIABLE GIT_SUBMOD_RESULT)
		if(NOT GIT_SUBMOD_RESULT EQUAL "0")
			message(FATAL_ERROR "git submodule update --init failed with ${GIT_SUBMOD_RESULT}, please checkout submodules")
		endif()
	endif()
endif()

# build for release if not set; otherwise, it's toolchain-dependant
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# enable compiler warnings as errors
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror")

add_subdirectory(extern)
add_subdirectory(src)

if (TEMPLATE_PROJECT_BUILD_TESTS OR TEMPLATE_PROJECT_BUILD_ALL)
	message(STATUS "${PROJECT_NAME} - Generating tests")
	include(CTest)
	add_subdirectory(test)
endif()