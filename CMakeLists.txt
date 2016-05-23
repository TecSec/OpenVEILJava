LIST(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmakemodules)

IF(WIN32)
	cmake_minimum_required(VERSION 3.1.3)
	set_property(GLOBAL PROPERTY USE_FOLDERS On)
ELSE()
	cmake_minimum_required(VERSION 3.1.3)
ENDIF()

project(OpenVEILjavaWrapper C CXX)

IF(WIN32)
	if(MSVC_IDE)
		set(TS_INSTALL_PREFIX       "c:/TecSec/VEIL_7-0")
	else(MSVC_IDE)
		set(TS_INSTALL_PREFIX       "c:/TecSec/VEIL_7-0")
	endif(MSVC_IDE)
	set(TS_INSTALL_PREFIX_DEBUG   "c:/TecSec/VEIL_7-0")
	set(TS_INSTALL_PREFIX_RELEASE "c:/TecSec/VEIL_7-0")
ELSE(WIN32)
	SET(TS_INSTALL_PREFIX "${CMAKE_SOURCE_DIR}/../local" CACHE STRING "The install path to use for Linux")
ENDIF(WIN32)

set(TS_MODULE OpenVEILJava)

include(tecsec_top)
include(precompiled.header)
set(TS_INSTALL_PREFIX ${TS_INSTALL_PREFIX}/${TS_TOOLSET})
include (tecsec_installdirs)

include(summary)
include(${ALLBIN_DIR}/VEILApiVersion.cmake)

set(CMAKE_BUILD_TYPE ${TS_VS_CONFIG} CACHE STRING "The configuration build type")
if (CMAKE_CONFIGURATION_TYPES)
  set (CMAKE_CONFIGURATION_TYPES ${TS_VS_CONFIG})
  set (CMAKE_CONFIGURATION_TYPES "${CMAKE_CONFIGURATION_TYPES}" CACHE STRING "Reset the configurations for ${VEILCORENAME}" )
endif()

set(VEIL_COPYRIGHT "Copyright (C) 2015 TecSec, Inc.  All Rights Reserved Worldwide.")


FIND_PACKAGE(Java COMPONENTS Runtime Development REQUIRED)
message(STATUS Java_FOUND = ${Java_FOUND})
message(STATUS Java_Development_FOUND = ${Java_Development_FOUND})
message(STATUS Java_JAVAH_EXECUTABLE = ${Java_JAVAH_EXECUTABLE})
message(STATUS Java_JAVAC_EXECUTABLE = ${Java_JAVAC_EXECUTABLE})
message(STATUS Java_VERSION_STRING = ${Java_VERSION_STRING})

include(UseJava)

FIND_PACKAGE(JNI REQUIRED)

message(STATUS JNI_FOUND = ${JNI_FOUND})
message(STATUS JNI_INCLUDE_DIRS = ${JNI_INCLUDE_DIRS})
message(STATUS JNI_LIBRARIES = ${JNI_LIBRARIES})
message(STATUS JAVA_JVM_LIBRARY = ${JAVA_JVM_LIBRARY})
message(STATUS JAVA_INCLUDE_PATH = ${JAVA_INCLUDE_PATH})

include_directories(${JNI_INCLUDE_DIRS})

add_uninstall()

set(CMAKE_JNI_TARGET TRUE) 
# set(CMAKE_JAVA_TARGET_VERSION "${OPENVEIL_VERSION}") 
file(GLOB JNI_SOURCES               com/tecsec/OpenVEIL/*.java)

add_jar(com.tecsec.OpenVEIL ${JNI_SOURCES})
get_target_property(_jarFile com.tecsec.OpenVEIL JAR_FILE)



add_subdirectory(OpenVEILWrapper)
add_subdirectory(Samples)

summary()

CopyImportTargetBinaries(VEILCore ${BIN_DIR})
CopyImportTargetBinaries(VEILCmsHeader ${BIN_DIR})
CopyImportTargetBinaries(VEILFileSupport ${BIN_DIR})
install_jar(com.tecsec.OpenVEIL ${BIN_DIR})

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/com_tecsec_OpenVEIL_Connector.h
		${CMAKE_CURRENT_BINARY_DIR}/com_tecsec_OpenVEIL_GenericConnector.h
		${CMAKE_CURRENT_BINARY_DIR}/com_tecsec_OpenVEIL_KeyVEILConnector.h
		${CMAKE_CURRENT_BINARY_DIR}/com_tecsec_OpenVEIL_Session.h
		${CMAKE_CURRENT_BINARY_DIR}/com_tecsec_OpenVEIL_Token.h
		${CMAKE_CURRENT_BINARY_DIR}/com_tecsec_OpenVEIL_Environment.h
		${CMAKE_CURRENT_BINARY_DIR}/com_tecsec_OpenVEIL_Favorite.h
		${CMAKE_CURRENT_BINARY_DIR}/com_tecsec_OpenVEIL_LoginStatus.h
	WORKING_DIRECTORY
		${CMAKE_CURRENT_SOURCE_DIR}
	COMMAND ${Java_JAVAH_EXECUTABLE} -d ${CMAKE_CURRENT_BINARY_DIR} -jni com.tecsec.OpenVEIL.Connector
	COMMAND ${Java_JAVAH_EXECUTABLE} -d ${CMAKE_CURRENT_BINARY_DIR} -jni com.tecsec.OpenVEIL.GenericConnector
	COMMAND ${Java_JAVAH_EXECUTABLE} -d ${CMAKE_CURRENT_BINARY_DIR} -jni com.tecsec.OpenVEIL.KeyVEILConnector
	COMMAND ${Java_JAVAH_EXECUTABLE} -d ${CMAKE_CURRENT_BINARY_DIR} -jni com.tecsec.OpenVEIL.Session
	COMMAND ${Java_JAVAH_EXECUTABLE} -d ${CMAKE_CURRENT_BINARY_DIR} -jni com.tecsec.OpenVEIL.Token
	COMMAND ${Java_JAVAH_EXECUTABLE} -d ${CMAKE_CURRENT_BINARY_DIR} -jni com.tecsec.OpenVEIL.Environment
	COMMAND ${Java_JAVAH_EXECUTABLE} -d ${CMAKE_CURRENT_BINARY_DIR} -jni com.tecsec.OpenVEIL.Favorite
	COMMAND ${Java_JAVAH_EXECUTABLE} -d ${CMAKE_CURRENT_BINARY_DIR} -jni com.tecsec.OpenVEIL.LoginStatus
)

add_custom_target(GenJNIHeader ALL SOURCES 
	com_tecsec_OpenVEIL_Connector.h 
	com_tecsec_OpenVEIL_GenericConnector.h 
	com_tecsec_OpenVEIL_KeyVEILConnector.h 
	com_tecsec_OpenVEIL_Session.h 
	com_tecsec_OpenVEIL_Token.h 
	com_tecsec_OpenVEIL_Environment.h 
	com_tecsec_OpenVEIL_Favorite.h 
	com_tecsec_OpenVEIL_LoginStatus.h 
	${JNI_SOURCES} 
	DEPENDS com.tecsec.OpenVEIL
)

#install_jni_symlink(com.tecsec.OpenVEIL ${JAVA_LIB_INSTALL_DIR})

# list(GET Boost_LIBRARIES 1 _tmp)
# get_filename_component(__boostPath ${_tmp} DIRECTORY)
# get_filename_component(__boostFile ${_tmp} NAME_WE)
# install(FILES ${__boostPath}/${__boostFile}${CMAKE_SHARED_LIBRARY_SUFFIX} DESTINATION ${BIN_DIR})

# DumpAllVariables()
# get_filename_component(__pythonPath ${PYTHON_EXECUTABLE} DIRECTORY)
# install(FILES ${__pythonPath}/python${PYTHON_VERSION_MAJOR}${PYTHON_VERSION_MINOR}${CMAKE_SHARED_LIBRARY_SUFFIX} DESTINATION ${BIN_DIR})
