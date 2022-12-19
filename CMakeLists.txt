project(project_name C)

file(GLOB_RECURSE COMMONS RELATIVE ${CMAKE_SOURCE_DIR} "xrdp/common/*.c")
file(GLOB_RECURSE SOURCES RELATIVE ${CMAKE_SOURCE_DIR} "xrdp/*.c")

ADD_EXECUTABLE( fuzzme main.c ${SOURCES} ${COMMONS})

find_package(OpenSSL REQUIRED)
target_link_libraries(fuzzme OpenSSL::SSL)
