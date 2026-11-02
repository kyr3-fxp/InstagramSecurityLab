# Instagram Security Lab (Entorno Educativo de Ciberseguridad Defensiva)

Este laboratorio ha sido diseñado con fines exclusivamente educativos y de auditoría defensiva. **No realiza peticiones hacia Instagram ni interactúa con servidores reales.** Su objetivo es enseñar y simular el funcionamiento de los controles de seguridad modernos de autenticación en arquitecturas web:

1. **Analizador de Seguridad:** Entropía de Shannon, detección de patrones débiles, cruce contra diccionarios conocidos de filtraciones y cálculo de vectores de riesgo.
2. **Simulador de Ataques Local:** Simula vectores habituales (*Brute Force*, *Credential Stuffing*, *Password Spraying*) frente a un servidor local simulado para evaluar la efectividad de:
   - Límites de tasa (*Sliding Window Rate Limiting*).
   - Bloqueo escalonado de cuenta (*Account Lockout*).
   - Retardo artificial progresivo (*Exponential Backoff / Artificial Latency*).
3. **Auditor de Protección de Cuentas:** Evaluación integral de la postura defensiva (2FA / MFA vía TOTP o llaves físicas FIDO2, higiene de sesiones activas, canales de recuperación) y generación de dictámenes de remediación.

---

## 🛠 Estructura del Proyecto

```
InstagramSecurityLab/
│
├── CMakeLists.txt                # Configuración de compilación CMake
├── build.bat                     # Script de compilación automática para Windows
│
├── include/
│   ├── security_analyzer.hpp     # Análisis estático y entropía de contraseñas
│   ├── auth_simulator.hpp        # Servidor de autenticación local y simulador de vectores
│   └── account_auditor.hpp       # Auditor de cumplimiento de seguridad y remediación
│
└── src/
    ├── security_analyzer.cpp     # Implementación del analizador
    ├── auth_simulator.cpp        # Implementación del servidor mock y simulador
    ├── account_auditor.cpp       # Lógica del informe de auditoría
    ├── main_gui.cpp              # Interfaz gráfica interactiva nativa Windows (Win32)
    └── main_cli_tests.cpp        # Suite de pruebas unitarias automatizadas por consola
```

---

## 🚀 Instrucciones de Compilación y Ejecución

### Opción 1: Compilación Automática (MSVC / MinGW)

Si tienes instalado Visual Studio (Developer Command Prompt) o MinGW (`g++`):
```cmd
cd InstagramSecurityLab
build.bat
```
El script detectará el compilador disponible y generará los ejecutables en la carpeta `bin/`.

### Opción 2: Usando CMake

```bash
cd InstagramSecurityLab
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

### Opción 3: Compilación Directa con MinGW (g++)

```bash
# Interfaz Gráfica (GUI)
g++ -std=c++17 -Iinclude src/main_gui.cpp src/security_analyzer.cpp src/auth_simulator.cpp src/account_auditor.cpp -o bin/InstagramSecurityLab.exe -mwindows -lcomctl32 -lgdi32 -luser32

# Suite de pruebas por consola
g++ -std=c++17 -Iinclude src/main_cli_tests.cpp src/security_analyzer.cpp src/auth_simulator.cpp src/account_auditor.cpp -o bin/SecurityLabTests.exe
```

---

## 🧪 Pruebas Seguras y Verificación

Para ejecutar la verificación automática de los mecanismos defensivos:
```cmd
.\bin\SecurityLabTests.exe
```

Para abrir el laboratorio interactivo con pestañas:
```cmd
.\bin\InstagramSecurityLab.exe
```
