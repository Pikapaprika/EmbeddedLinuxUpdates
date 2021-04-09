set(CMAKE_CXX_STANDARD 17)
set(CURL_LIBRARY, "-lcurl")
find_package(CURL REQUIRED)

add_executable(EntryPoint UpdateClient.cpp
        nlohmann/json.hpp UpdateDownloadClient.cpp UpdateDownloadClient.h)

include_directories(${CURL_INCLUDE_DIR})
target_link_libraries(EntryPoint ${CURL_LIBRARIES} Log ArtifactParser ImageWriter)
install(DIRECTORY DESTINATION ${test_install})
install(TARGETS EntryPoint DESTINATION test_install)
