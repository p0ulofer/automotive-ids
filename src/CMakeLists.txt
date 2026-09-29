cmake_minimum_required(VERSION 3.16)
project(ids_apps LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)
find_package(Boost 1.75 REQUIRED COMPONENTS filesystem system)
find_package(vsomeip3 REQUIRED)

add_executable(ids_server ids_server.cpp)
target_link_libraries(ids_server PRIVATE
    ${VSOMEIP_LIBRARIES}
    Boost::filesystem
    Boost::system
    Threads::Threads)

add_executable(ids_client ids_client.cpp)
target_link_libraries(ids_client PRIVATE
    ${VSOMEIP_LIBRARIES}
    Boost::filesystem
    Boost::system
    Threads::Threads)

# --- Fase 2: apps parametrizados para geracao de datasets normais ------------
add_executable(ids_dataset_server ids_dataset_server.cpp)
target_link_libraries(ids_dataset_server PRIVATE
    ${VSOMEIP_LIBRARIES}
    Boost::filesystem
    Boost::system
    Threads::Threads)

add_executable(ids_dataset_client ids_dataset_client.cpp)
target_link_libraries(ids_dataset_client PRIVATE
    ${VSOMEIP_LIBRARIES}
    Boost::filesystem
    Boost::system
    Threads::Threads)

install(TARGETS ids_server ids_client ids_dataset_server ids_dataset_client
        RUNTIME DESTINATION bin)
