cmake_minimum_required(VERSION 2.8.11)
project(intrustd)

set(CMAKE_CFLAGS_RELEASE "-O3")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

find_package(PkgConfig)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(ZLIB REQUIRED zlib)
PKG_SEARCH_MODULE(URIPARSER liburiparser REQUIRED)
# pkg_check_modules(USRSCTP usrsctp REQUIRED)
pkg_check_modules(SCTP libsctp REQUIRED)
pkg_check_modules(CURL libcurl REQUIRED)
pkg_check_modules(CHECK check REQUIRED)

find_package(Uthash)

include(CheckTypeSize)

SET(CMAKE_EXTRA_INCLUDE_FILES "sys/socket.h")
CHECK_TYPE_SIZE("((struct cmsghdr *) 0)->cmsg_len" CMSGLEN_SIZE)
SET(CMAKE_EXTRA_INCLUDE_FILES)

SET(INTRUSTD_CFLAGS ${OPENSSL_CFLAGS} ${ZLIB_CFLAGS} ${UTHASH_CFLAGS} ${CMAKE_THREAD_LIBS_INIT} ${URIPARSER_CFLAGS} ${CURL_CFLAGS} -DJSMN_STRICT=1 -DCMSGLEN_SIZE=${CMSGLEN_SIZE})

include_directories(common)
add_library(intrustd-common STATIC common/event.c common/static_bio.c
  common/directory.c common/stun.c common/util.c common/buffer.c
  common/sdp.c common/dtls.c common/download.c common/jsmn.c
  common/process.c )
target_compile_options(intrustd-common PUBLIC -Wall -Werror ${INTRUSTD_CFLAGS})

add_executable(flockd flockd/main.c flockd/configuration.c flockd/connection.c
  flockd/state.c flockd/service.c flockd/websocket.c flockd/client.c flockd/appliance.c
  flockd/personas.c)
target_link_libraries(flockd PUBLIC intrustd-common ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES} ${UTHASH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
target_compile_options(flockd PUBLIC -Wall ${INTRUSTD_CFLAGS})

add_library(libapplianced STATIC  applianced/configuration.c applianced/state.c
  applianced/bridge.c applianced/local.c applianced/flock.c applianced/persona.c
  applianced/pconn.c applianced/container.c applianced/update.c applianced/application.c
  applianced/token.c applianced/nat.c applianced/avahi.c)
target_compile_options(libapplianced PUBLIC -Wall ${INTRUSTD_CFLAGS})
target_link_libraries(libapplianced PUBLIC intrustd-common ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES} ${UTHASH_LIBRARIES} ${URIPARSER_LIBRARIES} ${CURL_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

add_executable(applianced applianced/main.c)
target_link_libraries(applianced PUBLIC intrustd-common libapplianced)
target_compile_options(applianced PUBLIC -Wall ${INTRUSTD_CFLAGS})

add_executable(webrtc-proxy webrtc-proxy/main.c)
target_compile_options(webrtc-proxy PUBLIC ${SCTP_CFLAGS})
target_link_libraries(webrtc-proxy ${SCTP_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} intrustd-common ${OPENSSL_LIBRARIES})

add_executable(persona-init init/persona.c init/init_common.c)
add_executable(app-instance-init init/app_instance.c init/init_common.c)

add_executable(appliancectl appliancectl/main.c appliancectl/common.c
  appliancectl/flock.c appliancectl/persona.c appliancectl/app.c
  appliancectl/container.c)
target_link_libraries(appliancectl intrustd-common ${OPENSSL_LIBRARIES})

add_executable(timer-test common/tests/timer-test.c)
target_link_libraries(timer-test intrustd-common ${CMAKE_THREAD_LIBS_INIT})

add_executable(shared-test common/tests/shared-test.c)

add_executable(appliance-tests applianced/tests/main.c applianced/tests/token.c)
target_link_libraries(appliance-tests PUBLIC intrustd-common libapplianced ${CHECK_LIBRARIES})

OPTION(WEBRTC_DEBUG
  "Build the webrtc-proxy for debugging"
  OFF)
IF(WEBRTC_DEBUG)
  ADD_DEFINITIONS(-DWEBRTC_PROXY_DEBUG)
  MESSAGE("Building webrtc-proxy for debugging")
ENDIF(WEBRTC_DEBUG)
