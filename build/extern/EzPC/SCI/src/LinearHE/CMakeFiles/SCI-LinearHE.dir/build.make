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
include extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/depend.make

# Include the progress variables for this target.
include extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/progress.make

# Include the compile flags for this target's objects.
include extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/flags.make

extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/conv-field.cpp.o: extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/flags.make
extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/conv-field.cpp.o: ../extern/EzPC/SCI/src/LinearHE/conv-field.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/conv-field.cpp.o"
	cd /root/PQC-mPSI/build/extern/EzPC/SCI/src/LinearHE && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/SCI-LinearHE.dir/conv-field.cpp.o -c /root/PQC-mPSI/extern/EzPC/SCI/src/LinearHE/conv-field.cpp

extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/conv-field.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/SCI-LinearHE.dir/conv-field.cpp.i"
	cd /root/PQC-mPSI/build/extern/EzPC/SCI/src/LinearHE && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/EzPC/SCI/src/LinearHE/conv-field.cpp > CMakeFiles/SCI-LinearHE.dir/conv-field.cpp.i

extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/conv-field.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/SCI-LinearHE.dir/conv-field.cpp.s"
	cd /root/PQC-mPSI/build/extern/EzPC/SCI/src/LinearHE && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/EzPC/SCI/src/LinearHE/conv-field.cpp -o CMakeFiles/SCI-LinearHE.dir/conv-field.cpp.s

extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/fc-field.cpp.o: extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/flags.make
extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/fc-field.cpp.o: ../extern/EzPC/SCI/src/LinearHE/fc-field.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/fc-field.cpp.o"
	cd /root/PQC-mPSI/build/extern/EzPC/SCI/src/LinearHE && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/SCI-LinearHE.dir/fc-field.cpp.o -c /root/PQC-mPSI/extern/EzPC/SCI/src/LinearHE/fc-field.cpp

extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/fc-field.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/SCI-LinearHE.dir/fc-field.cpp.i"
	cd /root/PQC-mPSI/build/extern/EzPC/SCI/src/LinearHE && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/EzPC/SCI/src/LinearHE/fc-field.cpp > CMakeFiles/SCI-LinearHE.dir/fc-field.cpp.i

extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/fc-field.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/SCI-LinearHE.dir/fc-field.cpp.s"
	cd /root/PQC-mPSI/build/extern/EzPC/SCI/src/LinearHE && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/EzPC/SCI/src/LinearHE/fc-field.cpp -o CMakeFiles/SCI-LinearHE.dir/fc-field.cpp.s

extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/elemwise-prod-field.cpp.o: extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/flags.make
extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/elemwise-prod-field.cpp.o: ../extern/EzPC/SCI/src/LinearHE/elemwise-prod-field.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/elemwise-prod-field.cpp.o"
	cd /root/PQC-mPSI/build/extern/EzPC/SCI/src/LinearHE && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/SCI-LinearHE.dir/elemwise-prod-field.cpp.o -c /root/PQC-mPSI/extern/EzPC/SCI/src/LinearHE/elemwise-prod-field.cpp

extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/elemwise-prod-field.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/SCI-LinearHE.dir/elemwise-prod-field.cpp.i"
	cd /root/PQC-mPSI/build/extern/EzPC/SCI/src/LinearHE && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/EzPC/SCI/src/LinearHE/elemwise-prod-field.cpp > CMakeFiles/SCI-LinearHE.dir/elemwise-prod-field.cpp.i

extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/elemwise-prod-field.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/SCI-LinearHE.dir/elemwise-prod-field.cpp.s"
	cd /root/PQC-mPSI/build/extern/EzPC/SCI/src/LinearHE && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/EzPC/SCI/src/LinearHE/elemwise-prod-field.cpp -o CMakeFiles/SCI-LinearHE.dir/elemwise-prod-field.cpp.s

extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/utils-HE.cpp.o: extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/flags.make
extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/utils-HE.cpp.o: ../extern/EzPC/SCI/src/LinearHE/utils-HE.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/utils-HE.cpp.o"
	cd /root/PQC-mPSI/build/extern/EzPC/SCI/src/LinearHE && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/SCI-LinearHE.dir/utils-HE.cpp.o -c /root/PQC-mPSI/extern/EzPC/SCI/src/LinearHE/utils-HE.cpp

extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/utils-HE.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/SCI-LinearHE.dir/utils-HE.cpp.i"
	cd /root/PQC-mPSI/build/extern/EzPC/SCI/src/LinearHE && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/EzPC/SCI/src/LinearHE/utils-HE.cpp > CMakeFiles/SCI-LinearHE.dir/utils-HE.cpp.i

extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/utils-HE.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/SCI-LinearHE.dir/utils-HE.cpp.s"
	cd /root/PQC-mPSI/build/extern/EzPC/SCI/src/LinearHE && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/EzPC/SCI/src/LinearHE/utils-HE.cpp -o CMakeFiles/SCI-LinearHE.dir/utils-HE.cpp.s

# Object files for target SCI-LinearHE
SCI__LinearHE_OBJECTS = \
"CMakeFiles/SCI-LinearHE.dir/conv-field.cpp.o" \
"CMakeFiles/SCI-LinearHE.dir/fc-field.cpp.o" \
"CMakeFiles/SCI-LinearHE.dir/elemwise-prod-field.cpp.o" \
"CMakeFiles/SCI-LinearHE.dir/utils-HE.cpp.o"

# External object files for target SCI-LinearHE
SCI__LinearHE_EXTERNAL_OBJECTS =

lib/libSCI-LinearHE.a: extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/conv-field.cpp.o
lib/libSCI-LinearHE.a: extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/fc-field.cpp.o
lib/libSCI-LinearHE.a: extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/elemwise-prod-field.cpp.o
lib/libSCI-LinearHE.a: extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/utils-HE.cpp.o
lib/libSCI-LinearHE.a: extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/build.make
lib/libSCI-LinearHE.a: extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking CXX static library ../../../../../lib/libSCI-LinearHE.a"
	cd /root/PQC-mPSI/build/extern/EzPC/SCI/src/LinearHE && $(CMAKE_COMMAND) -P CMakeFiles/SCI-LinearHE.dir/cmake_clean_target.cmake
	cd /root/PQC-mPSI/build/extern/EzPC/SCI/src/LinearHE && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/SCI-LinearHE.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/build: lib/libSCI-LinearHE.a

.PHONY : extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/build

extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/clean:
	cd /root/PQC-mPSI/build/extern/EzPC/SCI/src/LinearHE && $(CMAKE_COMMAND) -P CMakeFiles/SCI-LinearHE.dir/cmake_clean.cmake
.PHONY : extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/clean

extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/depend:
	cd /root/PQC-mPSI/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/PQC-mPSI /root/PQC-mPSI/extern/EzPC/SCI/src/LinearHE /root/PQC-mPSI/build /root/PQC-mPSI/build/extern/EzPC/SCI/src/LinearHE /root/PQC-mPSI/build/extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : extern/EzPC/SCI/src/LinearHE/CMakeFiles/SCI-LinearHE.dir/depend

