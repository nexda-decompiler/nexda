cmake_minimum_required(VERSION 3.10)
project(Nexda)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(SRC_DIR src)
set(BIN_DIR ${CMAKE_BINARY_DIR}/bin)

file(GLOB SRC_FILES "${SRC_DIR}/*.cpp")

add_custom_target(
  format
  COMMAND clang-format -i ${SRC_FILES}
)

add_custom_target(
  clean-binaries
  COMMAND ${CMAKE_COMMAND} -E remove_directory ${BIN_DIR}
)

foreach(SRC_FILE ${SRC_FILES})
  get_filename_component(EXE_NAME ${SRC_FILE} NAME_WE)
  add_executable(${EXE_NAME} ${SRC_FILE})
  set_target_properties(${EXE_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})
  
  # Link against the required libraries
  target_link_libraries(${EXE_NAME} PRIVATE 
    elf
  )
  
  # Include directories for Capstone and Z3
  target_include_directories(${EXE_NAME} PRIVATE 
  )
  
  install(TARGETS ${EXE_NAME} RUNTIME DESTINATION ${BIN_DIR})
endforeach()

add_custom_target(
  install_binaries
  COMMAND ${CMAKE_COMMAND} --build . --target install
  COMMAND ${CMAKE_COMMAND} -E echo "Binaries installed to ${BIN_DIR}"
)