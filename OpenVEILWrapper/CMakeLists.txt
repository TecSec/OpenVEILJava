INCLUDE_DIRECTORIES(${PUBLIC_BINARY_TOP_DIR})

set(CMAKE_DEBUG_POSTFIX "")
add_library(OpenVEILjavaWrapper SHARED 
	Connector.cpp 
	Environment.cpp 
	Session.cpp 
	Token.cpp 
	Favorite.cpp 
	handle.h
	Connector.h 
	Environment.h 
	Session.h 
	Token.h 
	Favorite.h 
	)

TARGET_LINK_LIBRARIES(OpenVEILjavaWrapper VEILCore VEILCmsHeader VEILFileSupport)
set_target_properties(OpenVEILjavaWrapper PROPERTIES VERSION ${OPENVEIL_VERSION} SOVERSION ${OPENVEIL_SO_VERSION})
add_dependencies(OpenVEILjavaWrapper com.tecsec.OpenVEIL GenJNIHeader)

install(TARGETS OpenVEILjavaWrapper ARCHIVE DESTINATION ${LIB_DIR} LIBRARY DESTINATION ${SHLIB_DIR} RUNTIME DESTINATION ${BIN_DIR} )