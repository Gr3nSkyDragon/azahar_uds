add_executable(azahar_virtual_air
    virtual_air_server.cpp
)

set_target_properties(azahar_virtual_air PROPERTIES OUTPUT_NAME "azahar-virtual-air")

target_link_libraries(azahar_virtual_air PRIVATE uds_virtual_air)
if (WIN32)
    target_link_libraries(azahar_virtual_air PRIVATE ws2_32)
endif()
