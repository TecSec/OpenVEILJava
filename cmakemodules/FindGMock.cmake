#	Copyright (c) 2015, TecSec, Inc.
#
#	Redistribution and use in source and binary forms, with or without
#	modification, are permitted provided that the following conditions are met:
#	
#		* Redistributions of source code must retain the above copyright
#		  notice, this list of conditions and the following disclaimer.
#		* Redistributions in binary form must reproduce the above copyright
#		  notice, this list of conditions and the following disclaimer in the
#		  documentation and/or other materials provided with the distribution.
#		* Neither the name of TecSec nor the names of the contributors may be
#		  used to endorse or promote products derived from this software 
#		  without specific prior written permission.
#		 
#	ALTERNATIVELY, provided that this notice is retained in full, this product
#	may be distributed under the terms of the GNU General Public License (GPL),
#	in which case the provisions of the GPL apply INSTEAD OF those given above.
#		 
#	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#	DISCLAIMED.  IN NO EVENT SHALL TECSEC BE LIABLE FOR ANY 
#	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#	LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

include (CheckIncludeFiles)
include (CheckLibraryExists)
include (CheckSymbolExists)

find_path(GMOCK_INCLUDE_DIR gmock/gmock.h
    HINTS
        $ENV{GMOCK_ROOT}/include
        ${GMOCK_ROOT}/include
)
mark_as_advanced(GMOCK_INCLUDE_DIR)
# if (NOT GMOCK_LIBRARIES)
    find_library(GMOCK_SHARED_LIBRARY_RELEASE NAMES gmock HINTS $ENV{GMOCK_ROOT}/lib${TS_LIB_DIR_SUFFIX} ${GMOCK_ROOT}/lib${TS_LIB_DIR_SUFFIX})
    find_library(GMOCK_SHARED_LIBRARY_RELWITHDEBINFO NAMES gmock HINTS $ENV{GMOCK_ROOT}/lib${TS_LIB_DIR_SUFFIX} ${GMOCK_ROOT}/lib${TS_LIB_DIR_SUFFIX})
    find_library(GMOCK_SHARED_LIBRARY_DEBUG NAMES gmockd HINTS $ENV{GMOCK_ROOT}/lib${TS_LIB_DIR_SUFFIX} ${GMOCK_ROOT}/lib${TS_LIB_DIR_SUFFIX})
	IF(WIN32)
		SET(_tmp ${CMAKE_FIND_LIBRARY_SUFFIXES})
		SET(CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_SHARED_LIBRARY_SUFFIX})
		find_library(GMOCK_SHARED_SO_RELEASE NAMES gmock HINTS $ENV{GMOCK_ROOT}/bin${TS_LIB_DIR_SUFFIX} ${GMOCK_ROOT}/bin${TS_LIB_DIR_SUFFIX})
		find_library(GMOCK_SHARED_SO_RELWITHDEBINFO NAMES gmock HINTS $ENV{GMOCK_ROOT}/bin${TS_LIB_DIR_SUFFIX} ${GMOCK_ROOT}/bin${TS_LIB_DIR_SUFFIX})
		find_library(GMOCK_SHARED_SO_DEBUG NAMES gmockd HINTS $ENV{GMOCK_ROOT}/bin${TS_LIB_DIR_SUFFIX} ${GMOCK_ROOT}/bin${TS_LIB_DIR_SUFFIX})
		SET(CMAKE_FIND_LIBRARY_SUFFIXES ${_tmp})
	endif(WIN32)
# endif ()

# handle the QUIETLY and REQUIRED arguments and set BZip2_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GMOCK
                                  REQUIRED_VARS GMOCK_SHARED_LIBRARY_RELEASE GMOCK_SHARED_LIBRARY_DEBUG GMOCK_INCLUDE_DIR
								  )

if(GMOCK_FOUND)
    set(GMOCK_INCLUDE_DIRS ${GMOCK_INCLUDE_DIR})
    set(GMOCK_LIBRARIES ${GMOCK_LIBRARY})

    if(NOT TARGET GMOCK)
		if(WIN32)
		  add_library(GMOCK SHARED IMPORTED)
		  set_property(TARGET GMOCK PROPERTY IMPORTED_LOCATION_DEBUG "${GMOCK_SHARED_SO_DEBUG}")
		  set_property(TARGET GMOCK PROPERTY IMPORTED_LOCATION_RELEASE "${GMOCK_SHARED_SO_RELEASE}")
		  set_property(TARGET GMOCK PROPERTY IMPORTED_LOCATION_RELWITHDEBINFO "${GMOCK_SHARED_SO_RELWITHDEBINFO}")
		  set_property(TARGET GMOCK PROPERTY IMPORTED_IMPLIB_DEBUG "${GMOCK_SHARED_LIBRARY_DEBUG}")
		  set_property(TARGET GMOCK PROPERTY IMPORTED_IMPLIB_RELEASE "${GMOCK_SHARED_LIBRARY_RELEASE}")
		  set_property(TARGET GMOCK PROPERTY IMPORTED_IMPLIB_RELWITHDEBINFO "${GMOCK_SHARED_LIBRARY_RELWITHDEBINFO}")
		  set_property(TARGET GMOCK PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${GMOCK_INCLUDE_DIRS}")
		else(WIN32)
		  add_library(GMOCK SHARED IMPORTED)
		  set_target_properties(GMOCK PROPERTIES
			IMPORTED_LOCATION_DEBUG "${GMOCK_SHARED_LIBRARY_DEBUG}"
			IMPORTED_LOCATION_RELEASE "${GMOCK_SHARED_LIBRARY_RELEASE}"
			IMPORTED_LOCATION_RELWITHDEBINFO "${GMOCK_SHARED_LIBRARY_RELWITHDEBINFO}"
			INTERFACE_INCLUDE_DIRECTORIES "${GMOCK_INCLUDE_DIRS}")
		endif(WIN32)
    endif()
   
endif()

mark_as_advanced(GMOCK_INCLUDE_DIR)
