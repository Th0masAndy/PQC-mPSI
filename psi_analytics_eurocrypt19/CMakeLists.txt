find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)

find_package(Boost COMPONENTS program_options REQUIRED)

if (NOT Boost_FOUND)
    message(FATAL_ERROR "Boost library not found.  Rerun cmake with -DCMAKE_PREFIX_PATH=\"<path to lib1>;<path to lib2>\"")
endif ()

find_library(NTL_LIB ntl)
if (NOT NTL_LIB)
    message(FATAL_ERROR "ntl library not found.  Rerun cmake with -DCMAKE_PREFIX_PATH=\"<path to lib1>;<path to lib2>\"")
endif ()

add_library(psi_analytics_eurocrypt19
        common/psi_analytics.cpp
        common/helpers.cpp
	      common/socket.cpp
        common/relaxed_opprf.cpp
        common/connection.cpp
        common/utils.cpp
        common/table_opprf.cpp
        polynomials/Mersenne.cpp
        polynomials/Poly.cpp
        ots/ots.cpp
        ots/block_op_ots.cpp
        )

set_target_properties(psi_analytics_eurocrypt19
        PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
        )

target_compile_options(psi_analytics_eurocrypt19
        PRIVATE
        -march=native
        #-std=c++11
        -ffunction-sections -mpclmul -mbmi2 -maes
        -mavx -msse2 -msse3 -msse4.1 -mrdseed
        #-march=haswell
        -Wall -Wno-strict-overflow -Wno-ignored-attributes -Wno-parentheses)

link_directories(/usr/ssl/lib/ $ENV{HOME}/libscapi/install/lib )

target_link_libraries(psi_analytics_eurocrypt19 INTERFACE
        #ABY::aby
        #ENCRYPTO_utils::encrypto_utils
        ${GLIB_LDFLAGS}
        gmp
        gmpxx
        ntl
        HashingTables
        libOTe
        MPCHonestMajority
        Boost::program_options
        Threads::Threads
        $ENV{HOME}/libscapi/build/NTL/src/ntl.a
        $ENV{HOME}/libscapi/libscapi.a
        OTExtensionBristol
        libsimpleot.a
        boost_system boost_thread pthread crypto dl ssl z
        # relic is a transitive dependency of libOTe right now
        # change relic to another library (if needed) if this changes
        relic_s
        )

target_include_directories(psi_analytics_eurocrypt19 PUBLIC
        ${PSI_ANALYTICS_SOURCE_ROOT}/psi_analytics_eurocrypt19
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/libOTe/cryptoTools
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/libOTe
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/ABY/src
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/ABY/extern/ENCRYPTO_utils/src
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/HashingTables
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/MPCHonestMajority
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/EzPC/SCI/src
        $ENV{HOME}/libscapi/build/NTL/include
        $ENV{HOME}/libscapi/install/include
        $ENV{HOME}
        $ENV{HOME}/libscapi/install/include/OTExtensionBristol
        ${GLIB_INCLUDE_DIRS}
        )

if (PSI_ANALYTICS_BUILD_EXAMPLE)
    add_executable(psi_analytics_eurocrypt19_example psi_analytics_example.cpp)

    target_link_libraries(psi_analytics_eurocrypt19_example PUBLIC
            psi_analytics_eurocrypt19
            )
    set_target_properties(psi_analytics_eurocrypt19_example
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endif (PSI_ANALYTICS_BUILD_EXAMPLE)

macro (add_test _name)
	add_executable(${_name} "tests/test_${_name}.cpp")
  target_link_libraries(${_name} PUBLIC psi_analytics_eurocrypt19)
  set_target_properties(${_name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  )
endmacro()

add_test(circuit)
