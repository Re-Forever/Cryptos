cmake_minimum_required(VERSION 3.15)
project(GM C)

set(CMAKE_C_STANDARD 11)

add_executable(GM main.c SM3.c SM3.h SM2.c SM2.h SM4.c SM4.h)