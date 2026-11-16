cmake_minimum_required(VERSION 3.24)
project(cachy_python_extension LANGUAGES C)
find_package(Python3 REQUIRED COMPONENTS Interpreter Development.Module)
Python3_add_library(cachy_extension MODULE WITH_SOABI extension.c)
set_target_properties(cachy_extension PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/module")
target_compile_options(cachy_extension PRIVATE -Wall -Wextra -Werror)
enable_testing()
add_test(NAME compiled-extension COMMAND "${Python3_EXECUTABLE}" -I -S -B
    "${CMAKE_CURRENT_SOURCE_DIR}/check_extension.py" --extension "$<TARGET_FILE:cachy_extension>"
    --expected-file "${CMAKE_CURRENT_SOURCE_DIR}/expected.txt")
install(TARGETS cachy_extension LIBRARY DESTINATION lib)
install(FILES LICENSE DESTINATION share/licenses/python-extension-fixture)
