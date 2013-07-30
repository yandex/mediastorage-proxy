cmake_minimum_required(VERSION 2.6)
set(TARGET mediastorage-proxy)

set(CMAKE_CXX_FLAGS "-O0 -Wall -pedantic -std=c++0x -g")

set(REQUIRED_LIBRARIES
	thevoid
	elliptics_cpp
	mastermind
	boost_system
	swarm
	msgpack
	)

set(SOURCE
	${PROJECT_SOURCE_DIR}/src/proxy.cpp
	${PROJECT_SOURCE_DIR}/src/lookup_result.cpp
	${PROJECT_SOURCE_DIR}/src/data_container.cpp
	)

include_directories(BEFORE ${PROJECT_SOURCE_DIR}/include)

add_executable(${TARGET} ${SOURCE})

target_link_libraries(${TARGET} ${REQUIRED_LIBRARIES})

install(TARGETS ${TARGET} DESTINATION bin/)
