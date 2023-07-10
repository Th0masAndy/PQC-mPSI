# Install script for directory: /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/relic" TYPE FILE FILES
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_alloc.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_arch.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_bc.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_bench.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_bn.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_core.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_cp.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_dv.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_eb.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_ec.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_ed.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_ep.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_epx.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_err.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_fb.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_fbx.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_fp.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_fpx.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_label.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_md.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_pc.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_pp.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_rand.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_test.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_types.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_util.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/relic/low" TYPE FILE FILES
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/low/relic_bn_low.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/low/relic_dv_low.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/low/relic_fb_low.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/low/relic_fp_low.h"
    "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/low/relic_fpx_low.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/relic" TYPE DIRECTORY FILES "/root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/cmake" TYPE FILE FILES "/root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/cmake/relic-config.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/ENCRYPTO_utils/extern/relic/src/cmake_install.cmake")

endif()

