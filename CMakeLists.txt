SET(LIB_NAME tamis)

cmake_minimum_required(VERSION 2.6)
if(COMMAND cmake_policy)
	cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

FIND_PATH(HAVE_DISASM_H dis-asm.h /usr/include/ /usr/local/include/)

IF(NOT HAVE_DISASM_H)
	MESSAGE(FATAL_ERROR "Please install the binutils-dev (Debian) or binutils-devel (RH) package")
ENDIF(NOT HAVE_DISASM_H)


ADD_LIBRARY(${LIB_NAME} SHARED tamis.c opcode.c)
ADD_DEFINITIONS(-D_GNU_SOURCE -D__USE_GNU -g -Wall)
SET_TARGET_PROPERTIES(${LIB_NAME} PROPERTIES LINK_FLAGS "-nostartfiles")

TARGET_LINK_LIBRARIES(${LIB_NAME} pthread opcodes bfd)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR})

ADD_EXECUTABLE(opcode opcode.c)
SET_TARGET_PROPERTIES(opcode PROPERTIES COMPILE_FLAGS "-DOPCODE_TEST")
TARGET_LINK_LIBRARIES(opcode opcodes bfd)

SET(TEST test1)
ADD_EXECUTABLE(${TEST} tests/${TEST}.c)
TARGET_LINK_LIBRARIES(${TEST} ${LIB_NAME})

SET(TEST test2)
ADD_EXECUTABLE(${TEST} tests/${TEST}.c)
TARGET_LINK_LIBRARIES(${TEST} ${LIB_NAME})

SET(TEST test3)
ADD_EXECUTABLE(${TEST} tests/${TEST}.c)
TARGET_LINK_LIBRARIES(${TEST} ${LIB_NAME})

SET(TEST test4)
ADD_EXECUTABLE(${TEST} tests/${TEST}.c)
TARGET_LINK_LIBRARIES(${TEST} ${LIB_NAME})

ENABLE_TESTING()
ADD_TEST(UnprotectedAccess ${CMAKE_SOURCE_DIR}/tests/test1.sh)
ADD_TEST(ProtectedAccess ${CMAKE_SOURCE_DIR}/tests/test2.sh)
ADD_TEST(ProtectedThreaded ${CMAKE_SOURCE_DIR}/tests/test3.sh)
ADD_TEST(Correctness ${CMAKE_SOURCE_DIR}/tests/test4.sh)
