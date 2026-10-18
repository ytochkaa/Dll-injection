cmake_minimum_required(VERSION 3.10)
project(DLLInjection LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(VirusDLL SHARED VirusDLL/Source.cpp)
set_target_properties(VirusDLL PROPERTIES PREFIX "")
target_link_libraries(VirusDLL PRIVATE psapi)

add_executable(TargetProcess TargetProcess/Source.cpp)

add_executable(DLLLoader DLLLoader/Source.cpp)

add_executable(DLLInjectorAsProcess DLLInjectorAsProcess/Source.cpp)

add_library(DllInjectorAsDll SHARED DllInjectorAsDll/Source.cpp)

# Эти настройки нужны для строк с префиксом L.
target_compile_definitions(DLLLoader PRIVATE UNICODE _UNICODE)
target_compile_definitions(DLLInjectorAsProcess PRIVATE UNICODE _UNICODE)
target_compile_definitions(DllInjectorAsDll PRIVATE UNICODE _UNICODE)
