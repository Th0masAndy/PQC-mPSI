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
include extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/depend.make

# Include the progress variables for this target.
include extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/progress.make

# Include the compile flags for this target's objects.
include extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/flags.make

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/alsz-ot-ext-rec.cpp.o: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/flags.make
extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/alsz-ot-ext-rec.cpp.o: ../extern/ABY/extern/OTExtension/ot/alsz-ot-ext-rec.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/zero-knowledge/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/alsz-ot-ext-rec.cpp.o"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/otextension.dir/ot/alsz-ot-ext-rec.cpp.o -c /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/alsz-ot-ext-rec.cpp

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/alsz-ot-ext-rec.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/otextension.dir/ot/alsz-ot-ext-rec.cpp.i"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/alsz-ot-ext-rec.cpp > CMakeFiles/otextension.dir/ot/alsz-ot-ext-rec.cpp.i

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/alsz-ot-ext-rec.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/otextension.dir/ot/alsz-ot-ext-rec.cpp.s"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/alsz-ot-ext-rec.cpp -o CMakeFiles/otextension.dir/ot/alsz-ot-ext-rec.cpp.s

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/alsz-ot-ext-snd.cpp.o: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/flags.make
extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/alsz-ot-ext-snd.cpp.o: ../extern/ABY/extern/OTExtension/ot/alsz-ot-ext-snd.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/zero-knowledge/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/alsz-ot-ext-snd.cpp.o"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/otextension.dir/ot/alsz-ot-ext-snd.cpp.o -c /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/alsz-ot-ext-snd.cpp

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/alsz-ot-ext-snd.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/otextension.dir/ot/alsz-ot-ext-snd.cpp.i"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/alsz-ot-ext-snd.cpp > CMakeFiles/otextension.dir/ot/alsz-ot-ext-snd.cpp.i

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/alsz-ot-ext-snd.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/otextension.dir/ot/alsz-ot-ext-snd.cpp.s"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/alsz-ot-ext-snd.cpp -o CMakeFiles/otextension.dir/ot/alsz-ot-ext-snd.cpp.s

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/iknp-ot-ext-rec.cpp.o: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/flags.make
extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/iknp-ot-ext-rec.cpp.o: ../extern/ABY/extern/OTExtension/ot/iknp-ot-ext-rec.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/zero-knowledge/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/iknp-ot-ext-rec.cpp.o"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/otextension.dir/ot/iknp-ot-ext-rec.cpp.o -c /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/iknp-ot-ext-rec.cpp

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/iknp-ot-ext-rec.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/otextension.dir/ot/iknp-ot-ext-rec.cpp.i"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/iknp-ot-ext-rec.cpp > CMakeFiles/otextension.dir/ot/iknp-ot-ext-rec.cpp.i

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/iknp-ot-ext-rec.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/otextension.dir/ot/iknp-ot-ext-rec.cpp.s"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/iknp-ot-ext-rec.cpp -o CMakeFiles/otextension.dir/ot/iknp-ot-ext-rec.cpp.s

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/iknp-ot-ext-snd.cpp.o: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/flags.make
extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/iknp-ot-ext-snd.cpp.o: ../extern/ABY/extern/OTExtension/ot/iknp-ot-ext-snd.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/zero-knowledge/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/iknp-ot-ext-snd.cpp.o"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/otextension.dir/ot/iknp-ot-ext-snd.cpp.o -c /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/iknp-ot-ext-snd.cpp

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/iknp-ot-ext-snd.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/otextension.dir/ot/iknp-ot-ext-snd.cpp.i"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/iknp-ot-ext-snd.cpp > CMakeFiles/otextension.dir/ot/iknp-ot-ext-snd.cpp.i

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/iknp-ot-ext-snd.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/otextension.dir/ot/iknp-ot-ext-snd.cpp.s"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/iknp-ot-ext-snd.cpp -o CMakeFiles/otextension.dir/ot/iknp-ot-ext-snd.cpp.s

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/kk-ot-ext-rec.cpp.o: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/flags.make
extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/kk-ot-ext-rec.cpp.o: ../extern/ABY/extern/OTExtension/ot/kk-ot-ext-rec.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/zero-knowledge/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/kk-ot-ext-rec.cpp.o"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/otextension.dir/ot/kk-ot-ext-rec.cpp.o -c /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/kk-ot-ext-rec.cpp

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/kk-ot-ext-rec.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/otextension.dir/ot/kk-ot-ext-rec.cpp.i"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/kk-ot-ext-rec.cpp > CMakeFiles/otextension.dir/ot/kk-ot-ext-rec.cpp.i

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/kk-ot-ext-rec.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/otextension.dir/ot/kk-ot-ext-rec.cpp.s"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/kk-ot-ext-rec.cpp -o CMakeFiles/otextension.dir/ot/kk-ot-ext-rec.cpp.s

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/kk-ot-ext-snd.cpp.o: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/flags.make
extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/kk-ot-ext-snd.cpp.o: ../extern/ABY/extern/OTExtension/ot/kk-ot-ext-snd.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/zero-knowledge/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/kk-ot-ext-snd.cpp.o"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/otextension.dir/ot/kk-ot-ext-snd.cpp.o -c /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/kk-ot-ext-snd.cpp

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/kk-ot-ext-snd.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/otextension.dir/ot/kk-ot-ext-snd.cpp.i"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/kk-ot-ext-snd.cpp > CMakeFiles/otextension.dir/ot/kk-ot-ext-snd.cpp.i

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/kk-ot-ext-snd.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/otextension.dir/ot/kk-ot-ext-snd.cpp.s"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/kk-ot-ext-snd.cpp -o CMakeFiles/otextension.dir/ot/kk-ot-ext-snd.cpp.s

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/naor-pinkas.cpp.o: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/flags.make
extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/naor-pinkas.cpp.o: ../extern/ABY/extern/OTExtension/ot/naor-pinkas.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/zero-knowledge/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/naor-pinkas.cpp.o"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/otextension.dir/ot/naor-pinkas.cpp.o -c /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/naor-pinkas.cpp

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/naor-pinkas.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/otextension.dir/ot/naor-pinkas.cpp.i"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/naor-pinkas.cpp > CMakeFiles/otextension.dir/ot/naor-pinkas.cpp.i

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/naor-pinkas.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/otextension.dir/ot/naor-pinkas.cpp.s"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/naor-pinkas.cpp -o CMakeFiles/otextension.dir/ot/naor-pinkas.cpp.s

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/nnob-ot-ext-rec.cpp.o: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/flags.make
extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/nnob-ot-ext-rec.cpp.o: ../extern/ABY/extern/OTExtension/ot/nnob-ot-ext-rec.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/zero-knowledge/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building CXX object extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/nnob-ot-ext-rec.cpp.o"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/otextension.dir/ot/nnob-ot-ext-rec.cpp.o -c /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/nnob-ot-ext-rec.cpp

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/nnob-ot-ext-rec.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/otextension.dir/ot/nnob-ot-ext-rec.cpp.i"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/nnob-ot-ext-rec.cpp > CMakeFiles/otextension.dir/ot/nnob-ot-ext-rec.cpp.i

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/nnob-ot-ext-rec.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/otextension.dir/ot/nnob-ot-ext-rec.cpp.s"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/nnob-ot-ext-rec.cpp -o CMakeFiles/otextension.dir/ot/nnob-ot-ext-rec.cpp.s

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/nnob-ot-ext-snd.cpp.o: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/flags.make
extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/nnob-ot-ext-snd.cpp.o: ../extern/ABY/extern/OTExtension/ot/nnob-ot-ext-snd.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/zero-knowledge/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building CXX object extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/nnob-ot-ext-snd.cpp.o"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/otextension.dir/ot/nnob-ot-ext-snd.cpp.o -c /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/nnob-ot-ext-snd.cpp

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/nnob-ot-ext-snd.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/otextension.dir/ot/nnob-ot-ext-snd.cpp.i"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/nnob-ot-ext-snd.cpp > CMakeFiles/otextension.dir/ot/nnob-ot-ext-snd.cpp.i

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/nnob-ot-ext-snd.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/otextension.dir/ot/nnob-ot-ext-snd.cpp.s"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/nnob-ot-ext-snd.cpp -o CMakeFiles/otextension.dir/ot/nnob-ot-ext-snd.cpp.s

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/ot-ext.cpp.o: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/flags.make
extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/ot-ext.cpp.o: ../extern/ABY/extern/OTExtension/ot/ot-ext.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/zero-knowledge/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Building CXX object extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/ot-ext.cpp.o"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/otextension.dir/ot/ot-ext.cpp.o -c /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/ot-ext.cpp

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/ot-ext.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/otextension.dir/ot/ot-ext.cpp.i"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/ot-ext.cpp > CMakeFiles/otextension.dir/ot/ot-ext.cpp.i

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/ot-ext.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/otextension.dir/ot/ot-ext.cpp.s"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/ot-ext.cpp -o CMakeFiles/otextension.dir/ot/ot-ext.cpp.s

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/ot-ext-rec.cpp.o: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/flags.make
extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/ot-ext-rec.cpp.o: ../extern/ABY/extern/OTExtension/ot/ot-ext-rec.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/zero-knowledge/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_11) "Building CXX object extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/ot-ext-rec.cpp.o"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/otextension.dir/ot/ot-ext-rec.cpp.o -c /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/ot-ext-rec.cpp

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/ot-ext-rec.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/otextension.dir/ot/ot-ext-rec.cpp.i"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/ot-ext-rec.cpp > CMakeFiles/otextension.dir/ot/ot-ext-rec.cpp.i

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/ot-ext-rec.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/otextension.dir/ot/ot-ext-rec.cpp.s"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/ot-ext-rec.cpp -o CMakeFiles/otextension.dir/ot/ot-ext-rec.cpp.s

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/ot-ext-snd.cpp.o: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/flags.make
extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/ot-ext-snd.cpp.o: ../extern/ABY/extern/OTExtension/ot/ot-ext-snd.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/zero-knowledge/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_12) "Building CXX object extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/ot-ext-snd.cpp.o"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/otextension.dir/ot/ot-ext-snd.cpp.o -c /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/ot-ext-snd.cpp

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/ot-ext-snd.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/otextension.dir/ot/ot-ext-snd.cpp.i"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/ot-ext-snd.cpp > CMakeFiles/otextension.dir/ot/ot-ext-snd.cpp.i

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/ot-ext-snd.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/otextension.dir/ot/ot-ext-snd.cpp.s"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/ot-ext-snd.cpp -o CMakeFiles/otextension.dir/ot/ot-ext-snd.cpp.s

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/pvwddh.cpp.o: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/flags.make
extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/pvwddh.cpp.o: ../extern/ABY/extern/OTExtension/ot/pvwddh.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/zero-knowledge/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_13) "Building CXX object extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/pvwddh.cpp.o"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/otextension.dir/ot/pvwddh.cpp.o -c /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/pvwddh.cpp

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/pvwddh.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/otextension.dir/ot/pvwddh.cpp.i"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/pvwddh.cpp > CMakeFiles/otextension.dir/ot/pvwddh.cpp.i

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/pvwddh.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/otextension.dir/ot/pvwddh.cpp.s"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/pvwddh.cpp -o CMakeFiles/otextension.dir/ot/pvwddh.cpp.s

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/simpleot.cpp.o: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/flags.make
extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/simpleot.cpp.o: ../extern/ABY/extern/OTExtension/ot/simpleot.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/zero-knowledge/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_14) "Building CXX object extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/simpleot.cpp.o"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/otextension.dir/ot/simpleot.cpp.o -c /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/simpleot.cpp

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/simpleot.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/otextension.dir/ot/simpleot.cpp.i"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/simpleot.cpp > CMakeFiles/otextension.dir/ot/simpleot.cpp.i

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/simpleot.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/otextension.dir/ot/simpleot.cpp.s"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension/ot/simpleot.cpp -o CMakeFiles/otextension.dir/ot/simpleot.cpp.s

# Object files for target otextension
otextension_OBJECTS = \
"CMakeFiles/otextension.dir/ot/alsz-ot-ext-rec.cpp.o" \
"CMakeFiles/otextension.dir/ot/alsz-ot-ext-snd.cpp.o" \
"CMakeFiles/otextension.dir/ot/iknp-ot-ext-rec.cpp.o" \
"CMakeFiles/otextension.dir/ot/iknp-ot-ext-snd.cpp.o" \
"CMakeFiles/otextension.dir/ot/kk-ot-ext-rec.cpp.o" \
"CMakeFiles/otextension.dir/ot/kk-ot-ext-snd.cpp.o" \
"CMakeFiles/otextension.dir/ot/naor-pinkas.cpp.o" \
"CMakeFiles/otextension.dir/ot/nnob-ot-ext-rec.cpp.o" \
"CMakeFiles/otextension.dir/ot/nnob-ot-ext-snd.cpp.o" \
"CMakeFiles/otextension.dir/ot/ot-ext.cpp.o" \
"CMakeFiles/otextension.dir/ot/ot-ext-rec.cpp.o" \
"CMakeFiles/otextension.dir/ot/ot-ext-snd.cpp.o" \
"CMakeFiles/otextension.dir/ot/pvwddh.cpp.o" \
"CMakeFiles/otextension.dir/ot/simpleot.cpp.o"

# External object files for target otextension
otextension_EXTERNAL_OBJECTS =

extern/ABY/lib/libotextension.a: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/alsz-ot-ext-rec.cpp.o
extern/ABY/lib/libotextension.a: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/alsz-ot-ext-snd.cpp.o
extern/ABY/lib/libotextension.a: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/iknp-ot-ext-rec.cpp.o
extern/ABY/lib/libotextension.a: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/iknp-ot-ext-snd.cpp.o
extern/ABY/lib/libotextension.a: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/kk-ot-ext-rec.cpp.o
extern/ABY/lib/libotextension.a: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/kk-ot-ext-snd.cpp.o
extern/ABY/lib/libotextension.a: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/naor-pinkas.cpp.o
extern/ABY/lib/libotextension.a: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/nnob-ot-ext-rec.cpp.o
extern/ABY/lib/libotextension.a: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/nnob-ot-ext-snd.cpp.o
extern/ABY/lib/libotextension.a: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/ot-ext.cpp.o
extern/ABY/lib/libotextension.a: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/ot-ext-rec.cpp.o
extern/ABY/lib/libotextension.a: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/ot-ext-snd.cpp.o
extern/ABY/lib/libotextension.a: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/pvwddh.cpp.o
extern/ABY/lib/libotextension.a: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/ot/simpleot.cpp.o
extern/ABY/lib/libotextension.a: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/build.make
extern/ABY/lib/libotextension.a: extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/zero-knowledge/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_15) "Linking CXX static library ../../lib/libotextension.a"
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && $(CMAKE_COMMAND) -P CMakeFiles/otextension.dir/cmake_clean_target.cmake
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/otextension.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/build: extern/ABY/lib/libotextension.a

.PHONY : extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/build

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/clean:
	cd /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension && $(CMAKE_COMMAND) -P CMakeFiles/otextension.dir/cmake_clean.cmake
.PHONY : extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/clean

extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/depend:
	cd /root/zero-knowledge/PQC-mPSI/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/zero-knowledge/PQC-mPSI /root/zero-knowledge/PQC-mPSI/extern/ABY/extern/OTExtension /root/zero-knowledge/PQC-mPSI/build /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension /root/zero-knowledge/PQC-mPSI/build/extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : extern/ABY/extern/OTExtension/CMakeFiles/otextension.dir/depend

