#
# CMake build system design considerations:
#
# - Include directories:
#   + Do not define include directories globally using the include_directories
#     command but rather at the target level using the
#     target_include_directories command. That way, it is easier to guarantee
#     that targets are built using the proper list of include directories.
#   + Use the PUBLIC and PRIVATE keywords to specify the scope of include
#     directories. That way, a target linking to a library (using the
#     target_link_libraries command) inherits from the library PUBLIC include
#     directories and not from the PRIVATE ones.
# - MBEDTLS_TARGET_PREFIX: CMake targets are designed to be alterable by calling
#   CMake in order to avoid target name clashes, via the use of
#   MBEDTLS_TARGET_PREFIX. The value of this variable is prefixed to the
#   mbedtls, mbedx509, mbedcrypto and apidoc targets.
#

# We specify a minimum requirement of 3.10.2, but for now use 3.5.1 here
# until our infrastructure catches up.
cmake_minimum_required(VERSION 3.5.1)

include(CMakePackageConfigHelpers)

# https://cmake.org/cmake/help/latest/policy/CMP0011.html
# Setting this policy is required in CMake >= 3.18.0, otherwise a warning is generated. The OLD
# policy setting is deprecated, and will be removed in future versions.
cmake_policy(SET CMP0011 NEW)
# https://cmake.org/cmake/help/latest/policy/CMP0012.html
# Setting the CMP0012 policy to NEW is required for FindPython3 to work with CMake 3.18.2
# (there is a bug in this particular version), otherwise, setting the CMP0012 policy is required
# for CMake versions >= 3.18.3 otherwise a deprecated warning is generated. The OLD policy setting
# is deprecated and will be removed in future versions.
cmake_policy(SET CMP0012 NEW)

project("mbed TLS" C)

include(GNUInstallDirs)

# Determine if mbed TLS is being built as a subproject using add_subdirectory()
if(NOT DEFINED MBEDTLS_AS_SUBPROJECT)
  set(MBEDTLS_AS_SUBPROJECT ON)
  if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(MBEDTLS_AS_SUBPROJECT OFF)
  endif()
endif()

# Set the project root directory.
set(MBEDTLS_DIR ${CMAKE_CURRENT_SOURCE_DIR})

option(UNSAFE_BUILD "Allow unsafe builds. These builds ARE NOT SECURE." OFF)
option(GEN_FILES "Generate the auto-generated files as needed" OFF)

option(DISABLE_PACKAGE_CONFIG_AND_INSTALL "Disable package configuration, target export and installation" ${MBEDTLS_AS_SUBPROJECT})

string(REGEX MATCH "Clang" CMAKE_COMPILER_IS_CLANG "${CMAKE_C_COMPILER_ID}")
string(REGEX MATCH "GNU" CMAKE_COMPILER_IS_GNU "${CMAKE_C_COMPILER_ID}")
string(REGEX MATCH "IAR" CMAKE_COMPILER_IS_IAR "${CMAKE_C_COMPILER_ID}")
string(REGEX MATCH "MSVC" CMAKE_COMPILER_IS_MSVC "${CMAKE_C_COMPILER_ID}")

# If this is the root project add longer list of available CMAKE_BUILD_TYPE values
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}
        CACHE STRING "Choose the type of build: None Debug Release Coverage ASan ASanDbg MemSan MemSanDbg Check CheckFull"
        FORCE)
endif()

# Create a symbolic link from ${base_name} in the binary directory
# to the corresponding path in the source directory.
# Note: Copies the file(s) on Windows.
function(link_to_source base_name)
    set(link "${CMAKE_CURRENT_BINARY_DIR}/${base_name}")
    set(target "${CMAKE_CURRENT_SOURCE_DIR}/${base_name}")

    # Linking to non-existent file is not desirable. At best you will have a
    # dangling link, but when building in tree, this can create a symbolic link
    # to itself.
    if (EXISTS ${target} AND NOT EXISTS ${link})
        if (CMAKE_HOST_UNIX)
            execute_process(COMMAND ln -s ${target} ${link}
                RESULT_VARIABLE result
                ERROR_VARIABLE output)

            if (NOT ${result} EQUAL 0)
                message(FATAL_ERROR "Could not create symbolic link for: ${target} --> ${output}")
            endif()
        else()
            if (IS_DIRECTORY ${target})
                file(GLOB_RECURSE files FOLLOW_SYMLINKS LIST_DIRECTORIES false RELATIVE ${target} "${target}/*")
                foreach(file IN LISTS files)
                    configure_file("${target}/${file}" "${link}/${file}" COPYONLY)
                endforeach(file)
            else()
                configure_file(${target} ${link} COPYONLY)
            endif()
        endif()
    endif()
endfunction(link_to_source)

# Get the filename without the final extension (i.e. convert "a.b.c" to "a.b")
function(get_name_without_last_ext dest_var full_name)
    # Split into a list on '.' (but a cmake list is just a ';'-separated string)
    string(REPLACE "." ";" ext_parts "${full_name}")
    # Remove the last item if there are more than one
    list(LENGTH ext_parts ext_parts_len)
    if (${ext_parts_len} GREATER "1")
        math(EXPR ext_parts_last_item "${ext_parts_len} - 1")
        list(REMOVE_AT ext_parts ${ext_parts_last_item})
    endif()
    # Convert back to a string by replacing separators with '.'
    string(REPLACE ";" "." no_ext_name "${ext_parts}")
    # Copy into the desired variable
    set(${dest_var} ${no_ext_name} PARENT_SCOPE)
endfunction(get_name_without_last_ext)

string(REGEX MATCH "Clang" CMAKE_COMPILER_IS_CLANG "${CMAKE_C_COMPILER_ID}")

include(CheckCCompilerFlag)

set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_COLOR_MAKEFILE OFF)
set(CMAKE_INSTALL_MESSAGE NEVER)

if(CMAKE_COMPILER_IS_GNU)
    # some warnings we want are not available with old GCC versions
    # note: starting with CMake 2.8 we could use CMAKE_C_COMPILER_VERSION
    execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion
                    OUTPUT_VARIABLE GCC_VERSION)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w")
    set(CMAKE_C_FLAGS_RELEASE     "-O2")
    set(CMAKE_C_FLAGS_DEBUG       "-O0 -g3")
    set(CMAKE_C_FLAGS_COVERAGE    "-O0 -g3 --coverage")
    set(CMAKE_C_FLAGS_ASAN        "-fsanitize=address -fno-common -fsanitize=undefined -fno-sanitize-recover=all -O3")
    set(CMAKE_C_FLAGS_ASANDBG     "-fsanitize=address -fno-common -fsanitize=undefined -fno-sanitize-recover=all -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls")
    set(CMAKE_C_FLAGS_CHECK       "-Os")
    set(CMAKE_C_FLAGS_CHECKFULL   "${CMAKE_C_FLAGS_CHECK} -Wcast-qual")
endif(CMAKE_COMPILER_IS_GNU)

if(CMAKE_COMPILER_IS_CLANG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w")
    set(CMAKE_C_FLAGS_RELEASE     "-O2")
    set(CMAKE_C_FLAGS_DEBUG       "-O0 -g3")
    set(CMAKE_C_FLAGS_COVERAGE    "-O0 -g3 --coverage")
    set(CMAKE_C_FLAGS_ASAN        "-fsanitize=address -fno-common -fsanitize=undefined -fno-sanitize-recover=all -O3")
    set(CMAKE_C_FLAGS_ASANDBG     "-fsanitize=address -fno-common -fsanitize=undefined -fno-sanitize-recover=all -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls")
    set(CMAKE_C_FLAGS_MEMSAN      "-fsanitize=memory -O3")
    set(CMAKE_C_FLAGS_MEMSANDBG   "-fsanitize=memory -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls -fsanitize-memory-track-origins=2")
    set(CMAKE_C_FLAGS_CHECK       "-Os")
endif(CMAKE_COMPILER_IS_CLANG)

if(CMAKE_COMPILER_IS_IAR)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --warn_about_c_style_casts -Ohz")
endif(CMAKE_COMPILER_IS_IAR)

if(CMAKE_COMPILER_IS_MSVC)
    # Strictest warnings, UTF-8 source and execution charset
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W0 /utf-8")
endif(CMAKE_COMPILER_IS_MSVC)

add_subdirectory(include)

add_subdirectory(library)

if(NOT DISABLE_PACKAGE_CONFIG_AND_INSTALL)
    configure_package_config_file(
        "cmake/MbedTLSConfig.cmake.in"
        "cmake/MbedTLSConfig.cmake"
            INSTALL_DESTINATION "cmake")

    write_basic_package_version_file(
        "cmake/MbedTLSConfigVersion.cmake"
            COMPATIBILITY SameMajorVersion
            VERSION 3.4.0)

    install(
        FILES "${CMAKE_CURRENT_BINARY_DIR}/cmake/MbedTLSConfig.cmake"
              "${CMAKE_CURRENT_BINARY_DIR}/cmake/MbedTLSConfigVersion.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/MbedTLS")

    export(
        EXPORT MbedTLSTargets
        NAMESPACE MbedTLS::
        FILE "cmake/MbedTLSTargets.cmake")

    install(
        EXPORT MbedTLSTargets
        NAMESPACE MbedTLS::
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/MbedTLS"
        FILE "MbedTLSTargets.cmake")

    if(CMAKE_VERSION VERSION_GREATER 3.15 OR CMAKE_VERSION VERSION_EQUAL 3.15)
        # Do not export the package by default
        cmake_policy(SET CMP0090 NEW)

        # Make this package visible to the system
        export(PACKAGE MbedTLS)
    endif()
endif()
