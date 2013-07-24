cmake_minimum_required(VERSION 2.6)
set(TARGET thevoid_elliptics)

set(CMAKE_CXX_FLAGS "-O0 -Wall -pedantic -std=c++0x")

set(REQUIRED_LIBRARIES
	thevoid
	elliptics_cpp
	mastermind
	)

set(SOURCE
	${PROJECT_SOURCE_DIR}/src/proxy.cpp
	${PROJECT_SOURCE_DIR}/src/lookup_result.cpp
	)

include_directories(BEFORE ${PROJECT_SOURCE_DIR}/include)

add_executable(${TARGET} ${SOURCE})

target_link_libraries(${TARGET} ${REQUIRED_LIBRARIES})
