cmake_minimum_required(VERSION 2.8 FATAL_ERROR)

project(packet_capture)

find_package(PCL 1.2 REQUIRED)

include_directories(${PCL_INCLUDE_DIRS} "/usr/include/pcap/")
link_directories(${PCL_LIBRARY_DIRS})
add_definitions(${PCL_DEFINITIONS})
include_directories(${PCAP_INCLUDE_DIRS})

add_executable (packet_capture packet_capture.cpp)
target_link_libraries (packet_capture ${PCL_LIBRARIES} "pcap")
