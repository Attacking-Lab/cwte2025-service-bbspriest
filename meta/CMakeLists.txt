# lint_cmake: -whitespace/indent

cmake_minimum_required(VERSION 3.18)
project(cryptoaccelerator)

set(CMAKE_CXX_STANDARD 17)
add_compile_options(-Wall -Wextra -O2)

if(GMP_INCLUDE_DIR AND GMP_LIBRARIES)
	set(GMP_FIND_QUIETLY TRUE)
endif()

find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_library(GMP_LIBRARIES NAMES gmp libgmp)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GMP DEFAULT_MSG GMP_INCLUDE_DIR GMP_LIBRARIES)

if (GMP_FOUND AND NOT TARGET gmp::gmp)
	set(_found_shared_libgmp FALSE)
	get_filename_component(_gmplib_suffix ${GMP_LIBRARIES} EXT)
	if (_gmplib_suffix STREQUAL ${CMAKE_STATIC_LIBRARY_SUFFIX})
		add_library(gmp::gmp STATIC IMPORTED) # for msvc
	else()
		set(_found_shared_libgmp TRUE)
		add_library(gmp::gmp SHARED IMPORTED)
	endif()
	set_target_properties(gmp::gmp PROPERTIES
		INTERFACE_INCLUDE_DIRECTORIES ${GMP_INCLUDE_DIR}
	)
	if (WIN32 AND _found_shared_libgmp)
		set_target_properties(gmp::gmp PROPERTIES
			IMPORTED_IMPLIB ${GMP_LIBRARIES}
		)
	else()
		set_target_properties(gmp::gmp PROPERTIES
			IMPORTED_LOCATION ${GMP_LIBRARIES}
		)
	endif()
endif()

mark_as_advanced(GMP_INCLUDE_DIR GMP_LIBRARIES)


find_package(Python 3.12
	REQUIRED COMPONENTS Interpreter Development.Module
	OPTIONAL_COMPONENTS Development.SABIModule)

include(FetchContent)

FetchContent_Declare(
	nanobind
	GIT_REPOSITORY https://github.com/wjakob/nanobind
	GIT_TAG v2.9.0
)

FetchContent_MakeAvailable(nanobind)

nanobind_add_module(
	cryptoaccelerator
# STABLE_ABI
# NB_STATIC
	cryptoAccelerator.cpp
)

target_link_libraries(${PROJECT_NAME} PRIVATE gmp::gmp)

# target_link_libraries(${PROJECT_NAME} PRIVATE
# 	"${GMP_DIR}/lib/libgmp.a"
# 	"${GMP_DIR}/lib/libgmpxx.a"
# )

# set(CMAKE_EXE_LINKER_FLAGS "-static")
