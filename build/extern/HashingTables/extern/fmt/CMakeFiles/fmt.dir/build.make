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

# Include any dependencies generated for this target.
include extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/depend.make

# Include the progress variables for this target.
include extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/progress.make

# Include the compile flags for this target's objects.
include extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/flags.make

extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/src/format.cc.o: extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/flags.make
extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/src/format.cc.o: ../extern/HashingTables/extern/fmt/src/format.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/zero-knowledge/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/src/format.cc.o"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/HashingTables/extern/fmt && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/fmt.dir/src/format.cc.o -c /root/zero-knowledge/PQC-mPSI/extern/HashingTables/extern/fmt/src/format.cc

extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/src/format.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/fmt.dir/src/format.cc.i"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/HashingTables/extern/fmt && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/zero-knowledge/PQC-mPSI/extern/HashingTables/extern/fmt/src/format.cc > CMakeFiles/fmt.dir/src/format.cc.i

extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/src/format.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/fmt.dir/src/format.cc.s"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/HashingTables/extern/fmt && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/zero-knowledge/PQC-mPSI/extern/HashingTables/extern/fmt/src/format.cc -o CMakeFiles/fmt.dir/src/format.cc.s

extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/src/posix.cc.o: extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/flags.make
extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/src/posix.cc.o: ../extern/HashingTables/extern/fmt/src/posix.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/zero-knowledge/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/src/posix.cc.o"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/HashingTables/extern/fmt && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/fmt.dir/src/posix.cc.o -c /root/zero-knowledge/PQC-mPSI/extern/HashingTables/extern/fmt/src/posix.cc

extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/src/posix.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/fmt.dir/src/posix.cc.i"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/HashingTables/extern/fmt && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/zero-knowledge/PQC-mPSI/extern/HashingTables/extern/fmt/src/posix.cc > CMakeFiles/fmt.dir/src/posix.cc.i

extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/src/posix.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/fmt.dir/src/posix.cc.s"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/HashingTables/extern/fmt && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/zero-knowledge/PQC-mPSI/extern/HashingTables/extern/fmt/src/posix.cc -o CMakeFiles/fmt.dir/src/posix.cc.s

# Object files for target fmt
fmt_OBJECTS = \
"CMakeFiles/fmt.dir/src/format.cc.o" \
"CMakeFiles/fmt.dir/src/posix.cc.o"

# External object files for target fmt
fmt_EXTERNAL_OBJECTS =

extern/HashingTables/extern/fmt/libfmt.so.5.3.1: extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/src/format.cc.o
extern/HashingTables/extern/fmt/libfmt.so.5.3.1: extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/src/posix.cc.o
extern/HashingTables/extern/fmt/libfmt.so.5.3.1: extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/build.make
extern/HashingTables/extern/fmt/libfmt.so.5.3.1: extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/zero-knowledge/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX shared library libfmt.so"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/HashingTables/extern/fmt && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/fmt.dir/link.txt --verbose=$(VERBOSE)
	cd /root/zero-knowledge/PQC-mPSI/build/extern/HashingTables/extern/fmt && $(CMAKE_COMMAND) -E cmake_symlink_library libfmt.so.5.3.1 libfmt.so.5 libfmt.so

extern/HashingTables/extern/fmt/libfmt.so.5: extern/HashingTables/extern/fmt/libfmt.so.5.3.1
	@$(CMAKE_COMMAND) -E touch_nocreate extern/HashingTables/extern/fmt/libfmt.so.5

extern/HashingTables/extern/fmt/libfmt.so: extern/HashingTables/extern/fmt/libfmt.so.5.3.1
	@$(CMAKE_COMMAND) -E touch_nocreate extern/HashingTables/extern/fmt/libfmt.so

# Rule to build all files generated by this target.
extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/build: extern/HashingTables/extern/fmt/libfmt.so

.PHONY : extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/build

extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/clean:
	cd /root/zero-knowledge/PQC-mPSI/build/extern/HashingTables/extern/fmt && $(CMAKE_COMMAND) -P CMakeFiles/fmt.dir/cmake_clean.cmake
.PHONY : extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/clean

extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/depend:
	cd /root/zero-knowledge/PQC-mPSI/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/zero-knowledge/PQC-mPSI /root/zero-knowledge/PQC-mPSI/extern/HashingTables/extern/fmt /root/zero-knowledge/PQC-mPSI/build /root/zero-knowledge/PQC-mPSI/build/extern/HashingTables/extern/fmt /root/zero-knowledge/PQC-mPSI/build/extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : extern/HashingTables/extern/fmt/CMakeFiles/fmt.dir/depend
