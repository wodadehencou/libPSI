
#############################################
# Build kkrt16_client.exe
#############################################

file(GLOB_RECURSE SRC_KKRT16_CLIENT ${CMAKE_SOURCE_DIR}/kkrt16_client/*.cpp)
include_directories(${CMAKE_SOURCE_DIR}/kkrt16_client/)

add_executable(kkrt16_client.exe ${SRC_KKRT16_CLIENT})


#############################################
#                 Link libOTe               #
#############################################

find_library(
    libOTe_Tests_LIB
    NAMES libOTe_Tests
    HINTS "${libOTe_Dirs}/lib/")

find_library(
    cryptoTools_Tests_LIB
    NAMES tests_cryptoTools
    HINTS "${libOTe_Dirs}/lib/")

target_link_libraries(kkrt16_client.exe libPSI_Tests libPSI ${libOTe_Tests_LIB} ${cryptoTools_Tests_LIB})
