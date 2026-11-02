@echo off
echo ================================================================
echo    Instagram Security Lab - Script de Compilacion (Windows)
echo ================================================================

where cl >nul 2>nul
if %errorlevel% equ 0 (
    echo [*] Compilador MSVC detectado. Compilando con cl.exe...
    if not exist bin mkdir bin
    cl.exe /EHsc /std:c++17 /Iinclude src\main_gui.cpp src\security_analyzer.cpp src\auth_simulator.cpp src\account_auditor.cpp /Fe:bin\InstagramSecurityLab.exe /link comctl32.lib user32.lib gdi32.lib
    cl.exe /EHsc /std:c++17 /Iinclude src\main_cli_tests.cpp src\security_analyzer.cpp src\auth_simulator.cpp src\account_auditor.cpp /Fe:bin\SecurityLabTests.exe
    goto DONE
)

where g++ >nul 2>nul
if %errorlevel% equ 0 (
    echo [*] Compilador MinGW/GCC detectado. Compilando con g++...
    if not exist bin mkdir bin
    g++ -std=c++17 -Iinclude src/main_gui.cpp src/security_analyzer.cpp src/auth_simulator.cpp src/account_auditor.cpp -o bin/InstagramSecurityLab.exe -mwindows -lcomctl32 -lgdi32 -luser32
    g++ -std=c++17 -Iinclude src/main_cli_tests.cpp src/security_analyzer.cpp src/auth_simulator.cpp src/account_auditor.cpp -o bin/SecurityLabTests.exe
    goto DONE
)

echo [!] No se encontro 'cl' ni 'g++' en el PATH actual.
echo     Para compilar con CMake:
echo       mkdir build ^&^& cd build
echo       cmake ..
echo       cmake --build . --config Release

:DONE
if exist bin\InstagramSecurityLab.exe (
    echo.
    echo [+] Compilacion exitosa. Ejecutables generados en .\bin\
    echo     GUI:   bin\InstagramSecurityLab.exe
    echo     Tests: bin\SecurityLabTests.exe
)
pause
