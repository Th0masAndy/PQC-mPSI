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
CMAKE_SOURCE_DIR = /root/PQC-mPSI

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/PQC-mPSI/build

# Include any dependencies generated for this target.
include extern/HashingTables/CMakeFiles/HashingTables.dir/depend.make

# Include the progress variables for this target.
include extern/HashingTables/CMakeFiles/HashingTables.dir/progress.make

# Include the compile flags for this target's objects.
include extern/HashingTables/CMakeFiles/HashingTables.dir/flags.make

extern/HashingTables/CMakeFiles/HashingTables.dir/common/hash_table_entry.cpp.o: extern/HashingTables/CMakeFiles/HashingTables.dir/flags.make
extern/HashingTables/CMakeFiles/HashingTables.dir/common/hash_table_entry.cpp.o: ../extern/HashingTables/common/hash_table_entry.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object extern/HashingTables/CMakeFiles/HashingTables.dir/common/hash_table_entry.cpp.o"
	cd /root/PQC-mPSI/build/extern/HashingTables && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/HashingTables.dir/common/hash_table_entry.cpp.o -c /root/PQC-mPSI/extern/HashingTables/common/hash_table_entry.cpp

extern/HashingTables/CMakeFiles/HashingTables.dir/common/hash_table_entry.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/HashingTables.dir/common/hash_table_entry.cpp.i"
	cd /root/PQC-mPSI/build/extern/HashingTables && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/HashingTables/common/hash_table_entry.cpp > CMakeFiles/HashingTables.dir/common/hash_table_entry.cpp.i

extern/HashingTables/CMakeFiles/HashingTables.dir/common/hash_table_entry.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/HashingTables.dir/common/hash_table_entry.cpp.s"
	cd /root/PQC-mPSI/build/extern/HashingTables && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/HashingTables/common/hash_table_entry.cpp -o CMakeFiles/HashingTables.dir/common/hash_table_entry.cpp.s

extern/HashingTables/CMakeFiles/HashingTables.dir/common/hashing.cpp.o: extern/HashingTables/CMakeFiles/HashingTables.dir/flags.make
extern/HashingTables/CMakeFiles/HashingTables.dir/common/hashing.cpp.o: ../extern/HashingTables/common/hashing.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object extern/HashingTables/CMakeFiles/HashingTables.dir/common/hashing.cpp.o"
	cd /root/PQC-mPSI/build/extern/HashingTables && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/HashingTables.dir/common/hashing.cpp.o -c /root/PQC-mPSI/extern/HashingTables/common/hashing.cpp

extern/HashingTables/CMakeFiles/HashingTables.dir/common/hashing.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/HashingTables.dir/common/hashing.cpp.i"
	cd /root/PQC-mPSI/build/extern/HashingTables && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/HashingTables/common/hashing.cpp > CMakeFiles/HashingTables.dir/common/hashing.cpp.i

extern/HashingTables/CMakeFiles/HashingTables.dir/common/hashing.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/HashingTables.dir/common/hashing.cpp.s"
	cd /root/PQC-mPSI/build/extern/HashingTables && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/HashingTables/common/hashing.cpp -o CMakeFiles/HashingTables.dir/common/hashing.cpp.s

extern/HashingTables/CMakeFiles/HashingTables.dir/cuckoo_hashing/cuckoo_hashing.cpp.o: extern/HashingTables/CMakeFiles/HashingTables.dir/flags.make
extern/HashingTables/CMakeFiles/HashingTables.dir/cuckoo_hashing/cuckoo_hashing.cpp.o: ../extern/HashingTables/cuckoo_hashing/cuckoo_hashing.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object extern/HashingTables/CMakeFiles/HashingTables.dir/cuckoo_hashing/cuckoo_hashing.cpp.o"
	cd /root/PQC-mPSI/build/extern/HashingTables && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/HashingTables.dir/cuckoo_hashing/cuckoo_hashing.cpp.o -c /root/PQC-mPSI/extern/HashingTables/cuckoo_hashing/cuckoo_hashing.cpp

extern/HashingTables/CMakeFiles/HashingTables.dir/cuckoo_hashing/cuckoo_hashing.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/HashingTables.dir/cuckoo_hashing/cuckoo_hashing.cpp.i"
	cd /root/PQC-mPSI/build/extern/HashingTables && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/HashingTables/cuckoo_hashing/cuckoo_hashing.cpp > CMakeFiles/HashingTables.dir/cuckoo_hashing/cuckoo_hashing.cpp.i

extern/HashingTables/CMakeFiles/HashingTables.dir/cuckoo_hashing/cuckoo_hashing.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/HashingTables.dir/cuckoo_hashing/cuckoo_hashing.cpp.s"
	cd /root/PQC-mPSI/build/extern/HashingTables && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/HashingTables/cuckoo_hashing/cuckoo_hashing.cpp -o CMakeFiles/HashingTables.dir/cuckoo_hashing/cuckoo_hashing.cpp.s

extern/HashingTables/CMakeFiles/HashingTables.dir/simple_hashing/simple_hashing.cpp.o: extern/HashingTables/CMakeFiles/HashingTables.dir/flags.make
extern/HashingTables/CMakeFiles/HashingTables.dir/simple_hashing/simple_hashing.cpp.o: ../extern/HashingTables/simple_hashing/simple_hashing.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object extern/HashingTables/CMakeFiles/HashingTables.dir/simple_hashing/simple_hashing.cpp.o"
	cd /root/PQC-mPSI/build/extern/HashingTables && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/HashingTables.dir/simple_hashing/simple_hashing.cpp.o -c /root/PQC-mPSI/extern/HashingTables/simple_hashing/simple_hashing.cpp

extern/HashingTables/CMakeFiles/HashingTables.dir/simple_hashing/simple_hashing.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/HashingTables.dir/simple_hashing/simple_hashing.cpp.i"
	cd /root/PQC-mPSI/build/extern/HashingTables && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/HashingTables/simple_hashing/simple_hashing.cpp > CMakeFiles/HashingTables.dir/simple_hashing/simple_hashing.cpp.i

extern/HashingTables/CMakeFiles/HashingTables.dir/simple_hashing/simple_hashing.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/HashingTables.dir/simple_hashing/simple_hashing.cpp.s"
	cd /root/PQC-mPSI/build/extern/HashingTables && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/HashingTables/simple_hashing/simple_hashing.cpp -o CMakeFiles/HashingTables.dir/simple_hashing/simple_hashing.cpp.s

# Object files for target HashingTables
HashingTables_OBJECTS = \
"CMakeFiles/HashingTables.dir/common/hash_table_entry.cpp.o" \
"CMakeFiles/HashingTables.dir/common/hashing.cpp.o" \
"CMakeFiles/HashingTables.dir/cuckoo_hashing/cuckoo_hashing.cpp.o" \
"CMakeFiles/HashingTables.dir/simple_hashing/simple_hashing.cpp.o"

# External object files for target HashingTables
HashingTables_EXTERNAL_OBJECTS =

extern/HashingTables/libHashingTables.a: extern/HashingTables/CMakeFiles/HashingTables.dir/common/hash_table_entry.cpp.o
extern/HashingTables/libHashingTables.a: extern/HashingTables/CMakeFiles/HashingTables.dir/common/hashing.cpp.o
extern/HashingTables/libHashingTables.a: extern/HashingTables/CMakeFiles/HashingTables.dir/cuckoo_hashing/cuckoo_hashing.cpp.o
extern/HashingTables/libHashingTables.a: extern/HashingTables/CMakeFiles/HashingTables.dir/simple_hashing/simple_hashing.cpp.o
extern/HashingTables/libHashingTables.a: extern/HashingTables/CMakeFiles/HashingTables.dir/build.make
extern/HashingTables/libHashingTables.a: extern/HashingTables/CMakeFiles/HashingTables.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking CXX static library libHashingTables.a"
	cd /root/PQC-mPSI/build/extern/HashingTables && $(CMAKE_COMMAND) -P CMakeFiles/HashingTables.dir/cmake_clean_target.cmake
	cd /root/PQC-mPSI/build/extern/HashingTables && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/HashingTables.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
extern/HashingTables/CMakeFiles/HashingTables.dir/build: extern/HashingTables/libHashingTables.a

.PHONY : extern/HashingTables/CMakeFiles/HashingTables.dir/build

extern/HashingTables/CMakeFiles/HashingTables.dir/clean:
	cd /root/PQC-mPSI/build/extern/HashingTables && $(CMAKE_COMMAND) -P CMakeFiles/HashingTables.dir/cmake_clean.cmake
.PHONY : extern/HashingTables/CMakeFiles/HashingTables.dir/clean

extern/HashingTables/CMakeFiles/HashingTables.dir/depend:
	cd /root/PQC-mPSI/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/PQC-mPSI /root/PQC-mPSI/extern/HashingTables /root/PQC-mPSI/build /root/PQC-mPSI/build/extern/HashingTables /root/PQC-mPSI/build/extern/HashingTables/CMakeFiles/HashingTables.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : extern/HashingTables/CMakeFiles/HashingTables.dir/depend

