# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/zero-knowledge/PQC-mPSI

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/zero-knowledge/PQC-mPSI/build

# Utility rule file for arith_objs.

# Include the progress variables for this target.
include extern/ABY/extern/ENCRYPTO_utils/extern/relic/src/CMakeFiles/arith_objs.dir/progress.make

arith_objs: extern/ABY/extern/ENCRYPTO_utils/extern/relic/src/CMakeFiles/arith_objs.dir/build.make

.PHONY : arith_objs

# Rule to build all files generated by this target.
extern/ABY/extern/ENCRYPTO_utils/extern/relic/src/CMakeFiles/arith_objs.dir/build: arith_objs

.PHONY : extern/ABY/extern/ENCRYPTO_utils/extern/relic/src/CMakeFiles/arith_objs.dir/build

extern/ABY/extern/ENCRYPTO_utils/extern/relic/src/CMakeFiles/arith_objs.dir/clean:
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/ENCRYPTO_utils/extern/relic/src && $(CMAKE_COMMAND) -P CMakeFiles/arith_objs.dir/cmake_clean.cmake
.PHONY : extern/ABY/extern/ENCRYPTO_utils/extern/relic/src/CMakeFiles/arith_objs.dir/clean

extern/ABY/extern/ENCRYPTO_utils/extern/relic/src/CMakeFiles/arith_objs.dir/depend:
	cd /root/zero-knowledge/PQC-mPSI/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/zero-knowledge/PQC-mPSI /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/ENCRYPTO_utils/extern/relic/src /root/zero-knowledge/PQC-mPSI/build /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/ENCRYPTO_utils/extern/relic/src /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/ENCRYPTO_utils/extern/relic/src/CMakeFiles/arith_objs.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : extern/ABY/extern/ENCRYPTO_utils/extern/relic/src/CMakeFiles/arith_objs.dir/depend

