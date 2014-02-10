cmake_minimum_required(VERSION 2.6)
set(TARGET mediastorage-proxy)

set(CMAKE_CXX_FLAGS "-Wall -pedantic -std=c++0x")

find_package(PkgConfig)
pkg_check_modules(glib-2.0 glib-2.0)
find_path(GLIB_INCLUDE_DIR glib.h HINTS ${glib-2.0_INCLUDE_DIRS})
find_path(GLIBCONFIG_INCLUDE_DIR glibconfig.h HINTS ${glib-2.0_INCLUDE_DIRS})
find_library(GLIB_LIBRARY glib-2.0 HINTS ${glib-2.0_INCLUDE_DIRS})

set(REQUIRED_LIBRARIES
	thevoid
	elliptics_cpp
	mastermind
	boost_system
	swarm
	msgpack
	${GLIB_LIBRARY}
	)

set(SOURCE
	${PROJECT_SOURCE_DIR}/src/proxy.cpp
	${PROJECT_SOURCE_DIR}/src/upload.cpp
	${PROJECT_SOURCE_DIR}/src/get.cpp
	${PROJECT_SOURCE_DIR}/src/delete.cpp
	${PROJECT_SOURCE_DIR}/src/lookup_result.cpp
	${PROJECT_SOURCE_DIR}/src/data_container.cpp
	)

include_directories(BEFORE ${PROJECT_SOURCE_DIR}/include)
include_directories(BEFORE ${GLIB_INCLUDE_DIR})
include_directories(BEFORE ${GLIBCONFIG_INCLUDE_DIR})

add_executable(${TARGET} ${SOURCE})

target_link_libraries(${TARGET} ${REQUIRED_LIBRARIES})

install(TARGETS ${TARGET} DESTINATION bin/)
install(FILES ubic/init.d/mediastorage-proxy DESTINATION /etc/init.d)
install(FILES ubic/service/mediastorage-proxy DESTINATION /etc/ubic/service)
install(FILES ubic/perl5/MDSProxy.pm DESTINATION /usr/share/perl5/Ubic/Service)
