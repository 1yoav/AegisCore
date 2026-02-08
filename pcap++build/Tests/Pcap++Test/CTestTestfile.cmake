# CMake generated Testfile for 
# Source directory: C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Tests/Pcap++Test
# Build directory: C:/Users/Cyber_User/Documents/AegisCore/pcap++build/Tests/Pcap++Test
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(Pcap++Test "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Tests/Pcap++Test/Bin/Pcap++Test.exe" "-n")
  set_tests_properties(Pcap++Test PROPERTIES  WORKING_DIRECTORY "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Tests/Pcap++Test/" _BACKTRACE_TRIPLES "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Tests/Pcap++Test/CMakeLists.txt;33;add_test;C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Tests/Pcap++Test/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(Pcap++Test "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Tests/Pcap++Test/Bin/Pcap++Test.exe" "-n")
  set_tests_properties(Pcap++Test PROPERTIES  WORKING_DIRECTORY "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Tests/Pcap++Test/" _BACKTRACE_TRIPLES "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Tests/Pcap++Test/CMakeLists.txt;33;add_test;C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Tests/Pcap++Test/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(Pcap++Test "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Tests/Pcap++Test/Bin/MinSizeRel/Pcap++Test.exe" "-n")
  set_tests_properties(Pcap++Test PROPERTIES  WORKING_DIRECTORY "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Tests/Pcap++Test/" _BACKTRACE_TRIPLES "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Tests/Pcap++Test/CMakeLists.txt;33;add_test;C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Tests/Pcap++Test/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(Pcap++Test "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Tests/Pcap++Test/Bin/RelWithDebInfo/Pcap++Test.exe" "-n")
  set_tests_properties(Pcap++Test PROPERTIES  WORKING_DIRECTORY "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Tests/Pcap++Test/" _BACKTRACE_TRIPLES "C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Tests/Pcap++Test/CMakeLists.txt;33;add_test;C:/Users/Cyber_User/Documents/Pcap++/PcapPlusPlus/Tests/Pcap++Test/CMakeLists.txt;0;")
else()
  add_test(Pcap++Test NOT_AVAILABLE)
endif()
