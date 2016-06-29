cmake_minimum_required(VERSION 2.6)

Project(CXX)

# Bring the included files into project
include_directories(include)

# add source files 
set (COMPLETETABLESOURCES src/JsonHelper.cpp src/completeTable.cpp)
set (TIMEWEAKNESSSOURCES src/timeWeakness.cpp)

add_definitions("-std=c++11")
add_definitions("-g")

add_executable(Stats ${COMPLETETABLESOURCES})
add_executable(Time ${TIMEWEAKNESSSOURCES})
