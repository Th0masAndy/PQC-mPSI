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
include extern/ABY/src/abycore/CMakeFiles/aby.dir/depend.make

# Include the progress variables for this target.
include extern/ABY/src/abycore/CMakeFiles/aby.dir/progress.make

# Include the compile flags for this target's objects.
include extern/ABY/src/abycore/CMakeFiles/aby.dir/flags.make

extern/ABY/src/abycore/CMakeFiles/aby.dir/aby/abyparty.cpp.o: extern/ABY/src/abycore/CMakeFiles/aby.dir/flags.make
extern/ABY/src/abycore/CMakeFiles/aby.dir/aby/abyparty.cpp.o: ../extern/ABY/src/abycore/aby/abyparty.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object extern/ABY/src/abycore/CMakeFiles/aby.dir/aby/abyparty.cpp.o"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/aby.dir/aby/abyparty.cpp.o -c /root/PQC-mPSI/extern/ABY/src/abycore/aby/abyparty.cpp

extern/ABY/src/abycore/CMakeFiles/aby.dir/aby/abyparty.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aby.dir/aby/abyparty.cpp.i"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/ABY/src/abycore/aby/abyparty.cpp > CMakeFiles/aby.dir/aby/abyparty.cpp.i

extern/ABY/src/abycore/CMakeFiles/aby.dir/aby/abyparty.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aby.dir/aby/abyparty.cpp.s"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/ABY/src/abycore/aby/abyparty.cpp -o CMakeFiles/aby.dir/aby/abyparty.cpp.s

extern/ABY/src/abycore/CMakeFiles/aby.dir/aby/abysetup.cpp.o: extern/ABY/src/abycore/CMakeFiles/aby.dir/flags.make
extern/ABY/src/abycore/CMakeFiles/aby.dir/aby/abysetup.cpp.o: ../extern/ABY/src/abycore/aby/abysetup.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object extern/ABY/src/abycore/CMakeFiles/aby.dir/aby/abysetup.cpp.o"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/aby.dir/aby/abysetup.cpp.o -c /root/PQC-mPSI/extern/ABY/src/abycore/aby/abysetup.cpp

extern/ABY/src/abycore/CMakeFiles/aby.dir/aby/abysetup.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aby.dir/aby/abysetup.cpp.i"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/ABY/src/abycore/aby/abysetup.cpp > CMakeFiles/aby.dir/aby/abysetup.cpp.i

extern/ABY/src/abycore/CMakeFiles/aby.dir/aby/abysetup.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aby.dir/aby/abysetup.cpp.s"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/ABY/src/abycore/aby/abysetup.cpp -o CMakeFiles/aby.dir/aby/abysetup.cpp.s

extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/abycircuit.cpp.o: extern/ABY/src/abycore/CMakeFiles/aby.dir/flags.make
extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/abycircuit.cpp.o: ../extern/ABY/src/abycore/circuit/abycircuit.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/abycircuit.cpp.o"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/aby.dir/circuit/abycircuit.cpp.o -c /root/PQC-mPSI/extern/ABY/src/abycore/circuit/abycircuit.cpp

extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/abycircuit.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aby.dir/circuit/abycircuit.cpp.i"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/ABY/src/abycore/circuit/abycircuit.cpp > CMakeFiles/aby.dir/circuit/abycircuit.cpp.i

extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/abycircuit.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aby.dir/circuit/abycircuit.cpp.s"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/ABY/src/abycore/circuit/abycircuit.cpp -o CMakeFiles/aby.dir/circuit/abycircuit.cpp.s

extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/arithmeticcircuits.cpp.o: extern/ABY/src/abycore/CMakeFiles/aby.dir/flags.make
extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/arithmeticcircuits.cpp.o: ../extern/ABY/src/abycore/circuit/arithmeticcircuits.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/arithmeticcircuits.cpp.o"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/aby.dir/circuit/arithmeticcircuits.cpp.o -c /root/PQC-mPSI/extern/ABY/src/abycore/circuit/arithmeticcircuits.cpp

extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/arithmeticcircuits.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aby.dir/circuit/arithmeticcircuits.cpp.i"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/ABY/src/abycore/circuit/arithmeticcircuits.cpp > CMakeFiles/aby.dir/circuit/arithmeticcircuits.cpp.i

extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/arithmeticcircuits.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aby.dir/circuit/arithmeticcircuits.cpp.s"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/ABY/src/abycore/circuit/arithmeticcircuits.cpp -o CMakeFiles/aby.dir/circuit/arithmeticcircuits.cpp.s

extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/booleancircuits.cpp.o: extern/ABY/src/abycore/CMakeFiles/aby.dir/flags.make
extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/booleancircuits.cpp.o: ../extern/ABY/src/abycore/circuit/booleancircuits.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/booleancircuits.cpp.o"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/aby.dir/circuit/booleancircuits.cpp.o -c /root/PQC-mPSI/extern/ABY/src/abycore/circuit/booleancircuits.cpp

extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/booleancircuits.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aby.dir/circuit/booleancircuits.cpp.i"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/ABY/src/abycore/circuit/booleancircuits.cpp > CMakeFiles/aby.dir/circuit/booleancircuits.cpp.i

extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/booleancircuits.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aby.dir/circuit/booleancircuits.cpp.s"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/ABY/src/abycore/circuit/booleancircuits.cpp -o CMakeFiles/aby.dir/circuit/booleancircuits.cpp.s

extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/circuit.cpp.o: extern/ABY/src/abycore/CMakeFiles/aby.dir/flags.make
extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/circuit.cpp.o: ../extern/ABY/src/abycore/circuit/circuit.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/circuit.cpp.o"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/aby.dir/circuit/circuit.cpp.o -c /root/PQC-mPSI/extern/ABY/src/abycore/circuit/circuit.cpp

extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/circuit.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aby.dir/circuit/circuit.cpp.i"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/ABY/src/abycore/circuit/circuit.cpp > CMakeFiles/aby.dir/circuit/circuit.cpp.i

extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/circuit.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aby.dir/circuit/circuit.cpp.s"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/ABY/src/abycore/circuit/circuit.cpp -o CMakeFiles/aby.dir/circuit/circuit.cpp.s

extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/share.cpp.o: extern/ABY/src/abycore/CMakeFiles/aby.dir/flags.make
extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/share.cpp.o: ../extern/ABY/src/abycore/circuit/share.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/share.cpp.o"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/aby.dir/circuit/share.cpp.o -c /root/PQC-mPSI/extern/ABY/src/abycore/circuit/share.cpp

extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/share.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aby.dir/circuit/share.cpp.i"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/ABY/src/abycore/circuit/share.cpp > CMakeFiles/aby.dir/circuit/share.cpp.i

extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/share.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aby.dir/circuit/share.cpp.s"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/ABY/src/abycore/circuit/share.cpp -o CMakeFiles/aby.dir/circuit/share.cpp.s

extern/ABY/src/abycore/CMakeFiles/aby.dir/DGK/dgkparty.cpp.o: extern/ABY/src/abycore/CMakeFiles/aby.dir/flags.make
extern/ABY/src/abycore/CMakeFiles/aby.dir/DGK/dgkparty.cpp.o: ../extern/ABY/src/abycore/DGK/dgkparty.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building CXX object extern/ABY/src/abycore/CMakeFiles/aby.dir/DGK/dgkparty.cpp.o"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/aby.dir/DGK/dgkparty.cpp.o -c /root/PQC-mPSI/extern/ABY/src/abycore/DGK/dgkparty.cpp

extern/ABY/src/abycore/CMakeFiles/aby.dir/DGK/dgkparty.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aby.dir/DGK/dgkparty.cpp.i"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/ABY/src/abycore/DGK/dgkparty.cpp > CMakeFiles/aby.dir/DGK/dgkparty.cpp.i

extern/ABY/src/abycore/CMakeFiles/aby.dir/DGK/dgkparty.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aby.dir/DGK/dgkparty.cpp.s"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/ABY/src/abycore/DGK/dgkparty.cpp -o CMakeFiles/aby.dir/DGK/dgkparty.cpp.s

extern/ABY/src/abycore/CMakeFiles/aby.dir/DJN/djnparty.cpp.o: extern/ABY/src/abycore/CMakeFiles/aby.dir/flags.make
extern/ABY/src/abycore/CMakeFiles/aby.dir/DJN/djnparty.cpp.o: ../extern/ABY/src/abycore/DJN/djnparty.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building CXX object extern/ABY/src/abycore/CMakeFiles/aby.dir/DJN/djnparty.cpp.o"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/aby.dir/DJN/djnparty.cpp.o -c /root/PQC-mPSI/extern/ABY/src/abycore/DJN/djnparty.cpp

extern/ABY/src/abycore/CMakeFiles/aby.dir/DJN/djnparty.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aby.dir/DJN/djnparty.cpp.i"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/ABY/src/abycore/DJN/djnparty.cpp > CMakeFiles/aby.dir/DJN/djnparty.cpp.i

extern/ABY/src/abycore/CMakeFiles/aby.dir/DJN/djnparty.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aby.dir/DJN/djnparty.cpp.s"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/ABY/src/abycore/DJN/djnparty.cpp -o CMakeFiles/aby.dir/DJN/djnparty.cpp.s

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/arithsharing.cpp.o: extern/ABY/src/abycore/CMakeFiles/aby.dir/flags.make
extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/arithsharing.cpp.o: ../extern/ABY/src/abycore/sharing/arithsharing.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Building CXX object extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/arithsharing.cpp.o"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/aby.dir/sharing/arithsharing.cpp.o -c /root/PQC-mPSI/extern/ABY/src/abycore/sharing/arithsharing.cpp

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/arithsharing.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aby.dir/sharing/arithsharing.cpp.i"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/ABY/src/abycore/sharing/arithsharing.cpp > CMakeFiles/aby.dir/sharing/arithsharing.cpp.i

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/arithsharing.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aby.dir/sharing/arithsharing.cpp.s"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/ABY/src/abycore/sharing/arithsharing.cpp -o CMakeFiles/aby.dir/sharing/arithsharing.cpp.s

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/boolsharing.cpp.o: extern/ABY/src/abycore/CMakeFiles/aby.dir/flags.make
extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/boolsharing.cpp.o: ../extern/ABY/src/abycore/sharing/boolsharing.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_11) "Building CXX object extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/boolsharing.cpp.o"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/aby.dir/sharing/boolsharing.cpp.o -c /root/PQC-mPSI/extern/ABY/src/abycore/sharing/boolsharing.cpp

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/boolsharing.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aby.dir/sharing/boolsharing.cpp.i"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/ABY/src/abycore/sharing/boolsharing.cpp > CMakeFiles/aby.dir/sharing/boolsharing.cpp.i

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/boolsharing.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aby.dir/sharing/boolsharing.cpp.s"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/ABY/src/abycore/sharing/boolsharing.cpp -o CMakeFiles/aby.dir/sharing/boolsharing.cpp.s

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/sharing.cpp.o: extern/ABY/src/abycore/CMakeFiles/aby.dir/flags.make
extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/sharing.cpp.o: ../extern/ABY/src/abycore/sharing/sharing.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_12) "Building CXX object extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/sharing.cpp.o"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/aby.dir/sharing/sharing.cpp.o -c /root/PQC-mPSI/extern/ABY/src/abycore/sharing/sharing.cpp

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/sharing.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aby.dir/sharing/sharing.cpp.i"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/ABY/src/abycore/sharing/sharing.cpp > CMakeFiles/aby.dir/sharing/sharing.cpp.i

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/sharing.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aby.dir/sharing/sharing.cpp.s"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/ABY/src/abycore/sharing/sharing.cpp -o CMakeFiles/aby.dir/sharing/sharing.cpp.s

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/splut.cpp.o: extern/ABY/src/abycore/CMakeFiles/aby.dir/flags.make
extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/splut.cpp.o: ../extern/ABY/src/abycore/sharing/splut.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_13) "Building CXX object extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/splut.cpp.o"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/aby.dir/sharing/splut.cpp.o -c /root/PQC-mPSI/extern/ABY/src/abycore/sharing/splut.cpp

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/splut.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aby.dir/sharing/splut.cpp.i"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/ABY/src/abycore/sharing/splut.cpp > CMakeFiles/aby.dir/sharing/splut.cpp.i

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/splut.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aby.dir/sharing/splut.cpp.s"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/ABY/src/abycore/sharing/splut.cpp -o CMakeFiles/aby.dir/sharing/splut.cpp.s

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/yaoclientsharing.cpp.o: extern/ABY/src/abycore/CMakeFiles/aby.dir/flags.make
extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/yaoclientsharing.cpp.o: ../extern/ABY/src/abycore/sharing/yaoclientsharing.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_14) "Building CXX object extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/yaoclientsharing.cpp.o"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/aby.dir/sharing/yaoclientsharing.cpp.o -c /root/PQC-mPSI/extern/ABY/src/abycore/sharing/yaoclientsharing.cpp

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/yaoclientsharing.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aby.dir/sharing/yaoclientsharing.cpp.i"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/ABY/src/abycore/sharing/yaoclientsharing.cpp > CMakeFiles/aby.dir/sharing/yaoclientsharing.cpp.i

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/yaoclientsharing.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aby.dir/sharing/yaoclientsharing.cpp.s"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/ABY/src/abycore/sharing/yaoclientsharing.cpp -o CMakeFiles/aby.dir/sharing/yaoclientsharing.cpp.s

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/yaoserversharing.cpp.o: extern/ABY/src/abycore/CMakeFiles/aby.dir/flags.make
extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/yaoserversharing.cpp.o: ../extern/ABY/src/abycore/sharing/yaoserversharing.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_15) "Building CXX object extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/yaoserversharing.cpp.o"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/aby.dir/sharing/yaoserversharing.cpp.o -c /root/PQC-mPSI/extern/ABY/src/abycore/sharing/yaoserversharing.cpp

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/yaoserversharing.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aby.dir/sharing/yaoserversharing.cpp.i"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/ABY/src/abycore/sharing/yaoserversharing.cpp > CMakeFiles/aby.dir/sharing/yaoserversharing.cpp.i

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/yaoserversharing.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aby.dir/sharing/yaoserversharing.cpp.s"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/ABY/src/abycore/sharing/yaoserversharing.cpp -o CMakeFiles/aby.dir/sharing/yaoserversharing.cpp.s

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/yaosharing.cpp.o: extern/ABY/src/abycore/CMakeFiles/aby.dir/flags.make
extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/yaosharing.cpp.o: ../extern/ABY/src/abycore/sharing/yaosharing.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_16) "Building CXX object extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/yaosharing.cpp.o"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/aby.dir/sharing/yaosharing.cpp.o -c /root/PQC-mPSI/extern/ABY/src/abycore/sharing/yaosharing.cpp

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/yaosharing.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aby.dir/sharing/yaosharing.cpp.i"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/ABY/src/abycore/sharing/yaosharing.cpp > CMakeFiles/aby.dir/sharing/yaosharing.cpp.i

extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/yaosharing.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aby.dir/sharing/yaosharing.cpp.s"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/ABY/src/abycore/sharing/yaosharing.cpp -o CMakeFiles/aby.dir/sharing/yaosharing.cpp.s

# Object files for target aby
aby_OBJECTS = \
"CMakeFiles/aby.dir/aby/abyparty.cpp.o" \
"CMakeFiles/aby.dir/aby/abysetup.cpp.o" \
"CMakeFiles/aby.dir/circuit/abycircuit.cpp.o" \
"CMakeFiles/aby.dir/circuit/arithmeticcircuits.cpp.o" \
"CMakeFiles/aby.dir/circuit/booleancircuits.cpp.o" \
"CMakeFiles/aby.dir/circuit/circuit.cpp.o" \
"CMakeFiles/aby.dir/circuit/share.cpp.o" \
"CMakeFiles/aby.dir/DGK/dgkparty.cpp.o" \
"CMakeFiles/aby.dir/DJN/djnparty.cpp.o" \
"CMakeFiles/aby.dir/sharing/arithsharing.cpp.o" \
"CMakeFiles/aby.dir/sharing/boolsharing.cpp.o" \
"CMakeFiles/aby.dir/sharing/sharing.cpp.o" \
"CMakeFiles/aby.dir/sharing/splut.cpp.o" \
"CMakeFiles/aby.dir/sharing/yaoclientsharing.cpp.o" \
"CMakeFiles/aby.dir/sharing/yaoserversharing.cpp.o" \
"CMakeFiles/aby.dir/sharing/yaosharing.cpp.o"

# External object files for target aby
aby_EXTERNAL_OBJECTS =

extern/ABY/lib/libaby.a: extern/ABY/src/abycore/CMakeFiles/aby.dir/aby/abyparty.cpp.o
extern/ABY/lib/libaby.a: extern/ABY/src/abycore/CMakeFiles/aby.dir/aby/abysetup.cpp.o
extern/ABY/lib/libaby.a: extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/abycircuit.cpp.o
extern/ABY/lib/libaby.a: extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/arithmeticcircuits.cpp.o
extern/ABY/lib/libaby.a: extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/booleancircuits.cpp.o
extern/ABY/lib/libaby.a: extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/circuit.cpp.o
extern/ABY/lib/libaby.a: extern/ABY/src/abycore/CMakeFiles/aby.dir/circuit/share.cpp.o
extern/ABY/lib/libaby.a: extern/ABY/src/abycore/CMakeFiles/aby.dir/DGK/dgkparty.cpp.o
extern/ABY/lib/libaby.a: extern/ABY/src/abycore/CMakeFiles/aby.dir/DJN/djnparty.cpp.o
extern/ABY/lib/libaby.a: extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/arithsharing.cpp.o
extern/ABY/lib/libaby.a: extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/boolsharing.cpp.o
extern/ABY/lib/libaby.a: extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/sharing.cpp.o
extern/ABY/lib/libaby.a: extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/splut.cpp.o
extern/ABY/lib/libaby.a: extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/yaoclientsharing.cpp.o
extern/ABY/lib/libaby.a: extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/yaoserversharing.cpp.o
extern/ABY/lib/libaby.a: extern/ABY/src/abycore/CMakeFiles/aby.dir/sharing/yaosharing.cpp.o
extern/ABY/lib/libaby.a: extern/ABY/src/abycore/CMakeFiles/aby.dir/build.make
extern/ABY/lib/libaby.a: extern/ABY/src/abycore/CMakeFiles/aby.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_17) "Linking CXX static library ../../lib/libaby.a"
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && $(CMAKE_COMMAND) -P CMakeFiles/aby.dir/cmake_clean_target.cmake
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/aby.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
extern/ABY/src/abycore/CMakeFiles/aby.dir/build: extern/ABY/lib/libaby.a

.PHONY : extern/ABY/src/abycore/CMakeFiles/aby.dir/build

extern/ABY/src/abycore/CMakeFiles/aby.dir/clean:
	cd /root/PQC-mPSI/build/extern/ABY/src/abycore && $(CMAKE_COMMAND) -P CMakeFiles/aby.dir/cmake_clean.cmake
.PHONY : extern/ABY/src/abycore/CMakeFiles/aby.dir/clean

extern/ABY/src/abycore/CMakeFiles/aby.dir/depend:
	cd /root/PQC-mPSI/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/PQC-mPSI /root/PQC-mPSI/extern/ABY/src/abycore /root/PQC-mPSI/build /root/PQC-mPSI/build/extern/ABY/src/abycore /root/PQC-mPSI/build/extern/ABY/src/abycore/CMakeFiles/aby.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : extern/ABY/src/abycore/CMakeFiles/aby.dir/depend

