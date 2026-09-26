cmake_minimum_required(VERSION 3.16)
set(IDF_TARGET esp32s3 CACHE STRING "this project's only target")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32_uds_bridge)
