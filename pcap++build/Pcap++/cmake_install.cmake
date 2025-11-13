# Install script for directory: C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Pcap++

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

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY OPTIONAL FILES "C:/Users/Cyber_User/Documents/AegisCore/pcap++build/Pcap++/Debug/Pcap++.lib")
  elseif(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY OPTIONAL FILES "C:/Users/Cyber_User/Documents/AegisCore/pcap++build/Pcap++/Release/Pcap++.lib")
  elseif(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY OPTIONAL FILES "C:/Users/Cyber_User/Documents/AegisCore/pcap++build/Pcap++/MinSizeRel/Pcap++.lib")
  elseif(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY OPTIONAL FILES "C:/Users/Cyber_User/Documents/AegisCore/pcap++build/Pcap++/RelWithDebInfo/Pcap++.lib")
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE SHARED_LIBRARY FILES "C:/Users/Cyber_User/Documents/AegisCore/pcap++build/Pcap++/Debug/Pcap++.dll")
  elseif(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE SHARED_LIBRARY FILES "C:/Users/Cyber_User/Documents/AegisCore/pcap++build/Pcap++/Release/Pcap++.dll")
  elseif(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE SHARED_LIBRARY FILES "C:/Users/Cyber_User/Documents/AegisCore/pcap++build/Pcap++/MinSizeRel/Pcap++.dll")
  elseif(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE SHARED_LIBRARY FILES "C:/Users/Cyber_User/Documents/AegisCore/pcap++build/Pcap++/RelWithDebInfo/Pcap++.dll")
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/pcapplusplus" TYPE FILE FILES
    "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Pcap++/header/Device.h"
    "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Pcap++/header/DeviceListBase.h"
    "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Pcap++/header/NetworkUtils.h"
    "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Pcap++/header/PcapDevice.h"
    "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Pcap++/header/PcapFileDevice.h"
    "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Pcap++/header/PcapFilter.h"
    "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Pcap++/header/PcapLiveDevice.h"
    "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Pcap++/header/PcapLiveDeviceList.h"
    "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Pcap++/header/RawSocketDevice.h"
    "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Pcap++/header/PcapRemoteDevice.h"
    "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Pcap++/header/PcapRemoteDeviceList.h"
    "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Pcap++/header/WinPcapLiveDevice.h"
    )
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "C:/Users/Cyber_User/Documents/AegisCore/pcap++build/Pcap++/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
