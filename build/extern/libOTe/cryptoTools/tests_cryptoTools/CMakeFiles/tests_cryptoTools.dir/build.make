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
include extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/depend.make

# Include the progress variables for this target.
include extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/progress.make

# Include the compile flags for this target's objects.
include extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/flags.make

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/AES_Tests.cpp.o: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/flags.make
extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/AES_Tests.cpp.o: ../extern/libOTe/cryptoTools/tests_cryptoTools/AES_Tests.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/AES_Tests.cpp.o"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tests_cryptoTools.dir/AES_Tests.cpp.o -c /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/AES_Tests.cpp

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/AES_Tests.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tests_cryptoTools.dir/AES_Tests.cpp.i"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/AES_Tests.cpp > CMakeFiles/tests_cryptoTools.dir/AES_Tests.cpp.i

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/AES_Tests.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tests_cryptoTools.dir/AES_Tests.cpp.s"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/AES_Tests.cpp -o CMakeFiles/tests_cryptoTools.dir/AES_Tests.cpp.s

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/BtChannel_Tests.cpp.o: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/flags.make
extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/BtChannel_Tests.cpp.o: ../extern/libOTe/cryptoTools/tests_cryptoTools/BtChannel_Tests.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/BtChannel_Tests.cpp.o"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tests_cryptoTools.dir/BtChannel_Tests.cpp.o -c /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/BtChannel_Tests.cpp

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/BtChannel_Tests.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tests_cryptoTools.dir/BtChannel_Tests.cpp.i"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/BtChannel_Tests.cpp > CMakeFiles/tests_cryptoTools.dir/BtChannel_Tests.cpp.i

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/BtChannel_Tests.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tests_cryptoTools.dir/BtChannel_Tests.cpp.s"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/BtChannel_Tests.cpp -o CMakeFiles/tests_cryptoTools.dir/BtChannel_Tests.cpp.s

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Circuit_Tests.cpp.o: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/flags.make
extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Circuit_Tests.cpp.o: ../extern/libOTe/cryptoTools/tests_cryptoTools/Circuit_Tests.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Circuit_Tests.cpp.o"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tests_cryptoTools.dir/Circuit_Tests.cpp.o -c /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/Circuit_Tests.cpp

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Circuit_Tests.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tests_cryptoTools.dir/Circuit_Tests.cpp.i"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/Circuit_Tests.cpp > CMakeFiles/tests_cryptoTools.dir/Circuit_Tests.cpp.i

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Circuit_Tests.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tests_cryptoTools.dir/Circuit_Tests.cpp.s"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/Circuit_Tests.cpp -o CMakeFiles/tests_cryptoTools.dir/Circuit_Tests.cpp.s

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Circuit_aes_Tests.cpp.o: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/flags.make
extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Circuit_aes_Tests.cpp.o: ../extern/libOTe/cryptoTools/tests_cryptoTools/Circuit_aes_Tests.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Circuit_aes_Tests.cpp.o"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tests_cryptoTools.dir/Circuit_aes_Tests.cpp.o -c /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/Circuit_aes_Tests.cpp

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Circuit_aes_Tests.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tests_cryptoTools.dir/Circuit_aes_Tests.cpp.i"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/Circuit_aes_Tests.cpp > CMakeFiles/tests_cryptoTools.dir/Circuit_aes_Tests.cpp.i

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Circuit_aes_Tests.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tests_cryptoTools.dir/Circuit_aes_Tests.cpp.s"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/Circuit_aes_Tests.cpp -o CMakeFiles/tests_cryptoTools.dir/Circuit_aes_Tests.cpp.s

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Common.cpp.o: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/flags.make
extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Common.cpp.o: ../extern/libOTe/cryptoTools/tests_cryptoTools/Common.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Common.cpp.o"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tests_cryptoTools.dir/Common.cpp.o -c /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/Common.cpp

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Common.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tests_cryptoTools.dir/Common.cpp.i"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/Common.cpp > CMakeFiles/tests_cryptoTools.dir/Common.cpp.i

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Common.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tests_cryptoTools.dir/Common.cpp.s"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/Common.cpp -o CMakeFiles/tests_cryptoTools.dir/Common.cpp.s

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Cuckoo_Tests.cpp.o: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/flags.make
extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Cuckoo_Tests.cpp.o: ../extern/libOTe/cryptoTools/tests_cryptoTools/Cuckoo_Tests.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Cuckoo_Tests.cpp.o"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tests_cryptoTools.dir/Cuckoo_Tests.cpp.o -c /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/Cuckoo_Tests.cpp

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Cuckoo_Tests.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tests_cryptoTools.dir/Cuckoo_Tests.cpp.i"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/Cuckoo_Tests.cpp > CMakeFiles/tests_cryptoTools.dir/Cuckoo_Tests.cpp.i

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Cuckoo_Tests.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tests_cryptoTools.dir/Cuckoo_Tests.cpp.s"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/Cuckoo_Tests.cpp -o CMakeFiles/tests_cryptoTools.dir/Cuckoo_Tests.cpp.s

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Ecc_Tests.cpp.o: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/flags.make
extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Ecc_Tests.cpp.o: ../extern/libOTe/cryptoTools/tests_cryptoTools/Ecc_Tests.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Ecc_Tests.cpp.o"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tests_cryptoTools.dir/Ecc_Tests.cpp.o -c /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/Ecc_Tests.cpp

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Ecc_Tests.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tests_cryptoTools.dir/Ecc_Tests.cpp.i"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/Ecc_Tests.cpp > CMakeFiles/tests_cryptoTools.dir/Ecc_Tests.cpp.i

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Ecc_Tests.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tests_cryptoTools.dir/Ecc_Tests.cpp.s"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/Ecc_Tests.cpp -o CMakeFiles/tests_cryptoTools.dir/Ecc_Tests.cpp.s

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Misc_Tests.cpp.o: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/flags.make
extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Misc_Tests.cpp.o: ../extern/libOTe/cryptoTools/tests_cryptoTools/Misc_Tests.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building CXX object extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Misc_Tests.cpp.o"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tests_cryptoTools.dir/Misc_Tests.cpp.o -c /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/Misc_Tests.cpp

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Misc_Tests.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tests_cryptoTools.dir/Misc_Tests.cpp.i"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/Misc_Tests.cpp > CMakeFiles/tests_cryptoTools.dir/Misc_Tests.cpp.i

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Misc_Tests.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tests_cryptoTools.dir/Misc_Tests.cpp.s"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/Misc_Tests.cpp -o CMakeFiles/tests_cryptoTools.dir/Misc_Tests.cpp.s

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/REcc_Tests.cpp.o: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/flags.make
extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/REcc_Tests.cpp.o: ../extern/libOTe/cryptoTools/tests_cryptoTools/REcc_Tests.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building CXX object extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/REcc_Tests.cpp.o"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tests_cryptoTools.dir/REcc_Tests.cpp.o -c /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/REcc_Tests.cpp

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/REcc_Tests.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tests_cryptoTools.dir/REcc_Tests.cpp.i"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/REcc_Tests.cpp > CMakeFiles/tests_cryptoTools.dir/REcc_Tests.cpp.i

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/REcc_Tests.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tests_cryptoTools.dir/REcc_Tests.cpp.s"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/REcc_Tests.cpp -o CMakeFiles/tests_cryptoTools.dir/REcc_Tests.cpp.s

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/SimpleCuckoo.cpp.o: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/flags.make
extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/SimpleCuckoo.cpp.o: ../extern/libOTe/cryptoTools/tests_cryptoTools/SimpleCuckoo.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Building CXX object extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/SimpleCuckoo.cpp.o"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tests_cryptoTools.dir/SimpleCuckoo.cpp.o -c /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/SimpleCuckoo.cpp

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/SimpleCuckoo.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tests_cryptoTools.dir/SimpleCuckoo.cpp.i"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/SimpleCuckoo.cpp > CMakeFiles/tests_cryptoTools.dir/SimpleCuckoo.cpp.i

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/SimpleCuckoo.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tests_cryptoTools.dir/SimpleCuckoo.cpp.s"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/SimpleCuckoo.cpp -o CMakeFiles/tests_cryptoTools.dir/SimpleCuckoo.cpp.s

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/UnitTests.cpp.o: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/flags.make
extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/UnitTests.cpp.o: ../extern/libOTe/cryptoTools/tests_cryptoTools/UnitTests.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_11) "Building CXX object extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/UnitTests.cpp.o"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tests_cryptoTools.dir/UnitTests.cpp.o -c /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/UnitTests.cpp

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/UnitTests.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tests_cryptoTools.dir/UnitTests.cpp.i"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/UnitTests.cpp > CMakeFiles/tests_cryptoTools.dir/UnitTests.cpp.i

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/UnitTests.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tests_cryptoTools.dir/UnitTests.cpp.s"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/UnitTests.cpp -o CMakeFiles/tests_cryptoTools.dir/UnitTests.cpp.s

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/WolfSSL_Tests.cpp.o: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/flags.make
extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/WolfSSL_Tests.cpp.o: ../extern/libOTe/cryptoTools/tests_cryptoTools/WolfSSL_Tests.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_12) "Building CXX object extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/WolfSSL_Tests.cpp.o"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tests_cryptoTools.dir/WolfSSL_Tests.cpp.o -c /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/WolfSSL_Tests.cpp

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/WolfSSL_Tests.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tests_cryptoTools.dir/WolfSSL_Tests.cpp.i"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/WolfSSL_Tests.cpp > CMakeFiles/tests_cryptoTools.dir/WolfSSL_Tests.cpp.i

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/WolfSSL_Tests.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tests_cryptoTools.dir/WolfSSL_Tests.cpp.s"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools/WolfSSL_Tests.cpp -o CMakeFiles/tests_cryptoTools.dir/WolfSSL_Tests.cpp.s

# Object files for target tests_cryptoTools
tests_cryptoTools_OBJECTS = \
"CMakeFiles/tests_cryptoTools.dir/AES_Tests.cpp.o" \
"CMakeFiles/tests_cryptoTools.dir/BtChannel_Tests.cpp.o" \
"CMakeFiles/tests_cryptoTools.dir/Circuit_Tests.cpp.o" \
"CMakeFiles/tests_cryptoTools.dir/Circuit_aes_Tests.cpp.o" \
"CMakeFiles/tests_cryptoTools.dir/Common.cpp.o" \
"CMakeFiles/tests_cryptoTools.dir/Cuckoo_Tests.cpp.o" \
"CMakeFiles/tests_cryptoTools.dir/Ecc_Tests.cpp.o" \
"CMakeFiles/tests_cryptoTools.dir/Misc_Tests.cpp.o" \
"CMakeFiles/tests_cryptoTools.dir/REcc_Tests.cpp.o" \
"CMakeFiles/tests_cryptoTools.dir/SimpleCuckoo.cpp.o" \
"CMakeFiles/tests_cryptoTools.dir/UnitTests.cpp.o" \
"CMakeFiles/tests_cryptoTools.dir/WolfSSL_Tests.cpp.o"

# External object files for target tests_cryptoTools
tests_cryptoTools_EXTERNAL_OBJECTS =

extern/libOTe/cryptoTools/tests_cryptoTools/libtests_cryptoTools.a: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/AES_Tests.cpp.o
extern/libOTe/cryptoTools/tests_cryptoTools/libtests_cryptoTools.a: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/BtChannel_Tests.cpp.o
extern/libOTe/cryptoTools/tests_cryptoTools/libtests_cryptoTools.a: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Circuit_Tests.cpp.o
extern/libOTe/cryptoTools/tests_cryptoTools/libtests_cryptoTools.a: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Circuit_aes_Tests.cpp.o
extern/libOTe/cryptoTools/tests_cryptoTools/libtests_cryptoTools.a: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Common.cpp.o
extern/libOTe/cryptoTools/tests_cryptoTools/libtests_cryptoTools.a: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Cuckoo_Tests.cpp.o
extern/libOTe/cryptoTools/tests_cryptoTools/libtests_cryptoTools.a: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Ecc_Tests.cpp.o
extern/libOTe/cryptoTools/tests_cryptoTools/libtests_cryptoTools.a: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/Misc_Tests.cpp.o
extern/libOTe/cryptoTools/tests_cryptoTools/libtests_cryptoTools.a: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/REcc_Tests.cpp.o
extern/libOTe/cryptoTools/tests_cryptoTools/libtests_cryptoTools.a: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/SimpleCuckoo.cpp.o
extern/libOTe/cryptoTools/tests_cryptoTools/libtests_cryptoTools.a: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/UnitTests.cpp.o
extern/libOTe/cryptoTools/tests_cryptoTools/libtests_cryptoTools.a: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/WolfSSL_Tests.cpp.o
extern/libOTe/cryptoTools/tests_cryptoTools/libtests_cryptoTools.a: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/build.make
extern/libOTe/cryptoTools/tests_cryptoTools/libtests_cryptoTools.a: extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/PQC-mPSI/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_13) "Linking CXX static library libtests_cryptoTools.a"
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && $(CMAKE_COMMAND) -P CMakeFiles/tests_cryptoTools.dir/cmake_clean_target.cmake
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/tests_cryptoTools.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/build: extern/libOTe/cryptoTools/tests_cryptoTools/libtests_cryptoTools.a

.PHONY : extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/build

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/clean:
	cd /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools && $(CMAKE_COMMAND) -P CMakeFiles/tests_cryptoTools.dir/cmake_clean.cmake
.PHONY : extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/clean

extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/depend:
	cd /root/PQC-mPSI/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/PQC-mPSI /root/PQC-mPSI/extern/libOTe/cryptoTools/tests_cryptoTools /root/PQC-mPSI/build /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools /root/PQC-mPSI/build/extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : extern/libOTe/cryptoTools/tests_cryptoTools/CMakeFiles/tests_cryptoTools.dir/depend

