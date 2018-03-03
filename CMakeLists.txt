cmake_minimum_required(VERSION 3.10)
project(Raw_socket C)

set(CMAKE_C_STANDARD 11)

add_executable(Raw_socket src/main.c src/raw.c headers/raw.h)