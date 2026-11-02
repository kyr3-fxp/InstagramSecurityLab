cmake_minimum_required(VERSION 3.16)
project(InstagramSecurityLab LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

set(CORE_SOURCES
    src/security_analyzer.cpp
    src/auth_simulator.cpp
    src/account_auditor.cpp
)

# 1. Target ejecutable de Pruebas Automatizadas en Consola (Multiplataforma)
add_executable(SecurityLabTests
    src/main_cli_tests.cpp
    ${CORE_SOURCES}
)

# 2. Target ejecutable Interfaz Grafica Nativa Windows (Win32 GUI)
if (WIN32)
    add_executable(InstagramSecurityLab WIN32
        src/main_gui.cpp
        ${CORE_SOURCES}
    )
    target_link_libraries(InstagramSecurityLab PRIVATE comctl32 gdi32 user32)
endif()
