cmake_minimum_required(VERSION 2.6)

# Bring the included files into project
include_directories(include)

# add source files
set (PRELIMINARYSTATS src/JsonHelper.cpp src/preliminaryStats.cpp)
set (COMPLETETABLESOURCES src/JsonHelper.cpp src/completeTable.cpp)
set (TIMEWEAKNESSSOURCES src/timeWeakness.cpp)
set (TREESTRUCTURECWE src/treeWeakness.cpp)
set (CAPECWITHTIME src/timeCAPEC.cpp)
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set (CMAKE_CXX_COMPILER_ID clang)

add_definitions("-std=c++11")
add_definitions("-g")

add_executable(CAPECWithTime    ${CAPECWITHTIME})
add_executable(PreliminaryStats ${PRELIMINARYSTATS})
add_executable(CompleteTable    ${COMPLETETABLESOURCES})
add_executable(TimeWeakness     ${TIMEWEAKNESSSOURCES})
add_executable(CWEWithTree      ${TREESTRUCTURECWE})
