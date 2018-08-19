cmake_minimum_required(VERSION 2.6)
PROJECT(storkd)

SET(Boost_USE_STATIC_LIBS OFF)
SET(Boost_USE_MULTITHREAD ON)
set(Boost_USE_STATIC_RUNTIME    OFF)
FIND_PACKAGE(Boost 1.60.0 REQUIRED COMPONENTS log filesystem program_options random unit_test_framework)
IF (Boost_FOUND)
  INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})
  LINK_DIRECTORIES(${Boost_LIBRARY_DIRS})
ENDIF (Boost_FOUND)

FIND_PACKAGE(PkgConfig REQUIRED)
PKG_SEARCH_MODULE(OPENSSL openssl REQUIRED)
PKG_SEARCH_MODULE(URIPARSER liburiparser REQUIRED)

SET(USED_LIBS ${Boost_LOG_LIBRARY} ${Boost_PROGRAM_OPTIONS_LIBRARY} ${Boost_FILESYSTEM_LIBRARY} ${Boost_RANDOM_LIBRARY})

ADD_LIBRARY(stork STATIC src/persona/profile.cpp src/nix.cpp src/proto.cpp
  src/local_proto.cpp src/uri.cpp
  src/unarchiver.cpp src/application/application.cpp src/flock/proto.cpp src/backend_common.cpp
  src/peer/initiator.cpp src/peer/session.cpp src/peer/ice.cpp src/peer/stun.cpp
  src/peer/certificate.cpp src/peer/dtls.cpp)
TARGET_COMPILE_OPTIONS(stork PUBLIC -D BOOST_ALL_DYN_LINK -std=c++1z -Wall -I../common/)
TARGET_LINK_LIBRARIES(stork ${USED_LIBS} ${OPENSSL_LIBRARIES} ${URIPARSER_LIBRARIES})

ADD_EXECUTABLE(storkd src/main.cpp src/appliance.cpp src/local_api.cpp
  src/util/fd.cpp
  src/backend.cpp src/application/manager.cpp src/application/manifest.cpp
  src/application/installer.cpp src/container/app_instance.cpp
  src/container/manager.cpp src/container/runtime.cpp src/container/init.cpp
  src/container/bridge.cpp src/container/persona.cpp)
TARGET_COMPILE_OPTIONS(storkd PUBLIC -D BOOST_ALL_DYN_LINK -std=c++1z -Wall -I../common/)
TARGET_LINK_LIBRARIES(storkd stork ${USED_LIBS} ${OPENSSL_LIBRARIES})

ADD_EXECUTABLE(storkctl src/storkctl.cpp src/storkctl/command.cpp
  src/storkctl/persona_command.cpp src/storkctl/application_command.cpp
  src/storkctl/flock_command.cpp)
TARGET_COMPILE_OPTIONS(storkd PUBLIC -std=c++1z -Wall)
TARGET_LINK_LIBRARIES(storkctl stork ${USED_LIBS})

ADD_EXECUTABLE(flockd src/flock/flockd.cpp src/flock/configuration.cpp src/flock/manager.cpp
  src/flock/backend.cpp)
TARGET_COMPILE_OPTIONS(flockd PUBLIC -std=c++1z -Wall)
TARGET_LINK_LIBRARIES(flockd stork ${USED_LIBS})

ADD_EXECUTABLE(stork-test test/session.cpp test/main.cpp)
TARGET_COMPILE_OPTIONS(stork-test PUBLIC -std=c++1z -Wall)
TARGET_INCLUDE_DIRECTORIES(stork-test PUBLIC ./src)
TARGET_LINK_LIBRARIES(stork-test stork ${USED_LIBS} ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY})

ADD_TEST(NAME unit COMMAND ./stork-test)
