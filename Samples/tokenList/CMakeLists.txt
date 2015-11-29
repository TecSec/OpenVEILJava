file(GLOB JNI_SOURCES               *.java)

set(CMAKE_JAVA_INCLUDE_PATH ${PUBLIC_BINARY_TOP_DIR}/com.tecsec.OpenVEIL.jar)
add_jar(tokenList ${JNI_SOURCES})
add_dependencies(tokenList com.tecsec.OpenVEIL)
get_target_property(_jarFile tokenList JAR_FILE)
set_target_properties(tokenList PROPERTIES FOLDER "Samples")

install_jar(tokenList ${BIN_DIR})
