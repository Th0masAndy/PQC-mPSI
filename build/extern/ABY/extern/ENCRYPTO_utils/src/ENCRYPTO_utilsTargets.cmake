# Generated by CMake

if("${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}" LESS 2.5)
   message(FATAL_ERROR "CMake >= 2.6.0 required")
endif()
cmake_policy(PUSH)
cmake_policy(VERSION 2.6)
#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Protect against multiple inclusion, which would fail when already imported targets are added once more.
set(_targetsDefined)
set(_targetsNotDefined)
set(_expectedTargets)
foreach(_expectedTarget ENCRYPTO_utils::encrypto_utils)
  list(APPEND _expectedTargets ${_expectedTarget})
  if(NOT TARGET ${_expectedTarget})
    list(APPEND _targetsNotDefined ${_expectedTarget})
  endif()
  if(TARGET ${_expectedTarget})
    list(APPEND _targetsDefined ${_expectedTarget})
  endif()
endforeach()
if("${_targetsDefined}" STREQUAL "${_expectedTargets}")
  unset(_targetsDefined)
  unset(_targetsNotDefined)
  unset(_expectedTargets)
  set(CMAKE_IMPORT_FILE_VERSION)
  cmake_policy(POP)
  return()
endif()
if(NOT "${_targetsDefined}" STREQUAL "")
  message(FATAL_ERROR "Some (but not all) targets in this export set were already defined.\nTargets Defined: ${_targetsDefined}\nTargets not yet defined: ${_targetsNotDefined}\n")
endif()
unset(_targetsDefined)
unset(_targetsNotDefined)
unset(_expectedTargets)


# Create imported target ENCRYPTO_utils::encrypto_utils
add_library(ENCRYPTO_utils::encrypto_utils STATIC IMPORTED)

set_target_properties(ENCRYPTO_utils::encrypto_utils PROPERTIES
  INTERFACE_COMPILE_DEFINITIONS "ECCLVL=251"
  INTERFACE_COMPILE_FEATURES "cxx_std_17"
  INTERFACE_INCLUDE_DIRECTORIES "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/src"
  INTERFACE_LINK_LIBRARIES "\$<LINK_ONLY:Boost::system>;\$<LINK_ONLY:Boost::thread>;GMP::GMP;GMP::GMPXX;OpenSSL::Crypto;RELIC::relic"
)

# Import target "ENCRYPTO_utils::encrypto_utils" for configuration "Release"
set_property(TARGET ENCRYPTO_utils::encrypto_utils APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(ENCRYPTO_utils::encrypto_utils PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "/root/zero-knowledge/PQC-mPSI/build/extern/ABY/lib/libencrypto_utils.a"
  )

# This file does not depend on other imported targets which have
# been exported from the same project but in a separate export set.

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
cmake_policy(POP)