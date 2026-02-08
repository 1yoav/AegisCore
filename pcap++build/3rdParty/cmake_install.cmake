# Install script for directory: C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/3rdParty

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "C:/Program Files (x86)/PcapPlusPlus")
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

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("C:/Users/Cyber_User/Documents/AegisCore/pcap++build/3rdParty/EndianPortable/cmake_install.cmake")
  include("C:/Users/Cyber_User/Documents/AegisCore/pcap++build/3rdParty/Getopt-for-Visual-Studio/cmake_install.cmake")
  include("C:/Users/Cyber_User/Documents/AegisCore/pcap++build/3rdParty/hash-library/cmake_install.cmake")
  include("C:/Users/Cyber_User/Documents/AegisCore/pcap++build/3rdParty/json/cmake_install.cmake")
  include("C:/Users/Cyber_User/Documents/AegisCore/pcap++build/3rdParty/LightPcapNg/cmake_install.cmake")
  include("C:/Users/Cyber_User/Documents/AegisCore/pcap++build/3rdParty/MemPlumber/MemPlumber/cmake_install.cmake")

endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "C:/Users/Cyber_User/Documents/AegisCore/pcap++build/3rdParty/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
