#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <sstream>
#include "../include/security_analyzer.hpp"
#include "../include/auth_simulator.hpp"
#include "../include/account_auditor.hpp"

#pragma comment(lib, "comctl32.lib")

// Component IDs
#define ID_TAB_CONTROL 1001
#define ID_BTN_ANALYZE_PW 1002
#define ID_BTN_RUN_BRUTE_FORCE 1003
#define ID_BTN_RUN_STUFFING 1004
#define ID_BTN_RESET_SERVER 1005
#define ID_BTN_RUN_AUDIT 1006
#define ID_BTN_EXPORT_AUDIT 1007

#define ID_EDIT_PW_INPUT 2001
#define ID_EDIT_PW_OUTPUT 2002
#define ID_EDIT_SIM_LOGS 2003
#define ID_EDIT_AUDIT_OUTPUT 2004
#define ID_CHK_MFA 2005
#define ID_CHK_REUSE 2006
#define ID_CHK_BACKUP 2007
#define ID_COMBO_MFA_TYPE 2008

// Global instances
static SecurityLab::SecurityAnalyzer g_analyzer;
static SecurityLab::LocalMockAuthServer g_server;
static SecurityLab::AccountAuditor g_auditor;

static HWND g_hTabCtrl = NULL;
static HWND g_hPageAnalyzer = NULL;
static HWND g_hPageSimulator = NULL;
static HWND g_hPageAuditor = NULL;

// Sub-controls
static HWND g_hEditPwInput = NULL;
static HWND g_hEditPwOutput = NULL;
static HWND g_hEditSimLogs = NULL;
static HWND g_hEditAuditOutput = NULL;
static HWND g_hChkMfa = NULL;
static HWND g_hChkReuse = NULL;
static HWND g_hChkBackup = NULL;
static HWND g_hComboMfaType = NULL;

void LogSim(const std::string& text) {
    if (!g_hEditSimLogs) return;
    int len = GetWindowTextLengthA(g_hEditSimLogs);
    SendMessageA(g_hEditSimLogs, EM_SETSEL, len, len);
    SendMessageA(g_hEditSimLogs, EM_REPLACESEL, FALSE, (LPARAM)text.c_str());
    SendMessageA(g_hEditSimLogs, EM_REPLACESEL, FALSE, (LPARAM)"\r\n");
}

void SetupAnalyzerTab(HWND hWndParent, HINSTANCE hInstance) {
    CreateWindowA("STATIC", "Contrasena de Prueba a Evaluar:", WS_CHILD | WS_VISIBLE,
                  20, 20, 250, 20, hWndParent, NULL, hInstance, NULL);

    g_hEditPwInput = CreateWindowA("EDIT", "InstaAdmin123!", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                  20, 45, 300, 25, hWndParent, (HMENU)ID_EDIT_PW_INPUT, hInstance, NULL);

    CreateWindowA("BUTTON", "Analizar Riesgo y Entropia", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                  330, 45, 200, 25, hWndParent, (HMENU)ID_BTN_ANALYZE_PW, hInstance, NULL);

    CreateWindowA("STATIC", "Resultado del Diagnostico:", WS_CHILD | WS_VISIBLE,
                  20, 85, 250, 20, hWndParent, NULL, hInstance, NULL);

    g_hEditPwOutput = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                                      WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                                      20, 110, 740, 360, hWndParent, (HMENU)ID_EDIT_PW_OUTPUT, hInstance, NULL);
}

void SetupSimulatorTab(HWND hWndParent, HINSTANCE hInstance) {
    CreateWindowA("STATIC", "Simulador Defensivo de Autenticacion (Servidor Local Seguro)", WS_CHILD | WS_VISIBLE,
                  20, 15, 500, 20, hWndParent, NULL, hInstance, NULL);

    CreateWindowA("BUTTON", "Simular Ataque Fuerza Bruta", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                  20, 40, 210, 30, hWndParent, (HMENU)ID_BTN_RUN_BRUTE_FORCE, hInstance, NULL);

    CreateWindowA("BUTTON", "Simular Credential Stuffing", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                  240, 40, 210, 30, hWndParent, (HMENU)ID_BTN_RUN_STUFFING, hInstance, NULL);

    CreateWindowA("BUTTON", "Reiniciar Servidor Local", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                  460, 40, 180, 30, hWndParent, (HMENU)ID_BTN_RESET_SERVER, hInstance, NULL);

    CreateWindowA("STATIC", "Logs de Auditoria y Mecanismos de Defensa:", WS_CHILD | WS_VISIBLE,
                  20, 80, 350, 20, hWndParent, NULL, hInstance, NULL);

    g_hEditSimLogs = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                                    WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                                    20, 105, 740, 365, hWndParent, (HMENU)ID_EDIT_SIM_LOGS, hInstance, NULL);
}

void SetupAuditorTab(HWND hWndParent, HINSTANCE hInstance) {
    CreateWindowA("STATIC", "Parametros de Configuracion de la Cuenta de Prueba:", WS_CHILD | WS_VISIBLE,
                  20, 15, 400, 20, hWndParent, NULL, hInstance, NULL);

    g_hChkMfa = CreateWindowA("BUTTON", "Tiene Autenticacion en Dos Pasos (2FA) activada",
                              WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                              20, 40, 350, 22, hWndParent, (HMENU)ID_CHK_MFA, hInstance, NULL);

    CreateWindowA("STATIC", "Metodo 2FA:", WS_CHILD | WS_VISIBLE,
                  20, 68, 90, 20, hWndParent, NULL, hInstance, NULL);

    g_hComboMfaType = CreateWindowA("COMBOBOX", "", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                                   115, 65, 230, 120, hWndParent, (HMENU)ID_COMBO_MFA_TYPE, hInstance, NULL);
    SendMessageA(g_hComboMfaType, CB_ADDSTRING, 0, (LPARAM)"None");
    SendMessageA(g_hComboMfaType, CB_ADDSTRING, 0, (LPARAM)"SMS");
    SendMessageA(g_hComboMfaType, CB_ADDSTRING, 0, (LPARAM)"TOTP_Authenticator");
    SendMessageA(g_hComboMfaType, CB_ADDSTRING, 0, (LPARAM)"SecurityKey_FIDO2");
    SendMessageA(g_hComboMfaType, CB_SETCURSEL, 2, 0);

    g_hChkReuse = CreateWindowA("BUTTON", "Reutiliza contrasena en otros sitios (Vulnerabilidad de cruce)",
                               WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                               20, 95, 450, 22, hWndParent, (HMENU)ID_CHK_REUSE, hInstance, NULL);

    g_hChkBackup = CreateWindowA("BUTTON", "Codigos de recuperacion offline generados y guardados",
                                WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                20, 120, 450, 22, hWndParent, (HMENU)ID_CHK_BACKUP, hInstance, NULL);

    CreateWindowA("BUTTON", "Ejecutar Auditoria Completa", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                  480, 50, 200, 35, hWndParent, (HMENU)ID_BTN_RUN_AUDIT, hInstance, NULL);

    CreateWindowA("STATIC", "Dictamen de Auditoria y Recomendaciones de Seguridad:", WS_CHILD | WS_VISIBLE,
                  20, 150, 400, 20, hWndParent, NULL, hInstance, NULL);

    g_hEditAuditOutput = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                                        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                                        20, 175, 740, 295, hWndParent, (HMENU)ID_EDIT_AUDIT_OUTPUT, hInstance, NULL);

    SendMessageA(g_hChkMfa, BM_SETCHECK, BST_CHECKED, 0);
    SendMessageA(g_hChkBackup, BM_SETCHECK, BST_CHECKED, 0);
}

void OnAnalyzePassword() {
    char buf[256];
    GetWindowTextA(g_hEditPwInput, buf, sizeof(buf));
    std::string pw(buf);

    auto result = g_analyzer.analyzePassword(pw);

    std::ostringstream ss;
    ss << "=== INFORME DE SEGURIDAD DE CONTRASENA ===\r\n";
    ss << "Contrasena analizada: " << pw << "\r\n";
    ss << "Puntaje de Fortaleza: " << result.score << "/100\r\n";
    ss << "Entropia Shannon Estimada: " << result.entropyBits << " bits\r\n";
    ss << "Nivel de Riesgo Evaluado: " << SecurityLab::SecurityAnalyzer::riskLevelToString(result.risk) << "\r\n\r\n";

    ss << "Indicadores Tecnicos:\r\n";
    ss << " - Mayusculas: " << (result.hasUppercase ? "Si" : "No") << "\r\n";
    ss << " - Minusculas: " << (result.hasLowercase ? "Si" : "No") << "\r\n";
    ss << " - Numeros: " << (result.hasDigits ? "Si" : "No") << "\r\n";
    ss << " - Caracteres Especiales: " << (result.hasSpecial ? "Si" : "No") << "\r\n";
    ss << " - Coincide con Diccionario Comun: " << (result.isCommonDictionary ? "ALERTA: SI" : "No") << "\r\n";
    ss << " - Patrones Secuenciales/Repetitivos: " << (result.hasRepetitivePatterns ? "ALERTA: SI" : "No") << "\r\n\r\n";

    if (!result.vulnerabilities.empty()) {
        ss << "Vulnerabilidades Detectadas:\r\n";
        for (const auto& v : result.vulnerabilities) {
            ss << " [!] " << v << "\r\n";
        }
        ss << "\r\n";
    }

    if (!result.recommendations.empty()) {
        ss << "Recomendaciones de Mitigacion:\r\n";
        for (const auto& r : result.recommendations) {
            ss << " [*] " << r << "\r\n";
        }
    }

    SetWindowTextA(g_hEditPwOutput, ss.str().c_str());
}

void OnRunBruteForceSim() {
    LogSim(">>> Iniciando simulacion de Ataque de Fuerza Bruta contra servidor local...");
    LogSim("    Politica activa: Max 5 req/min por IP, Bloqueo de cuenta tras 7 intentos.");

    std::vector<std::string> wordlist = {
        "123456", "password", "instagram", "insta2024", "letmein",
        "dragon", "master", "football", "admin123", "secure_P@ssw0rd!2026"
    };

    SecurityLab::AttackSimulator sim(g_server);
    auto report = sim.runBruteForceSimulation("test_user_victim", wordlist, "192.168.1.50");

    for (const auto& ev : report.logEvents) {
        LogSim("    " + ev);
    }

    std::ostringstream ss;
    ss << "=== RESUMEN DEFENSIVO ===\r\n"
       << "    Total de intentos simulados: " << report.totalAttempts << "\r\n"
       << "    Bloqueados por Rate Limiting (IP): " << report.blockedByRateLimit << "\r\n"
       << "    Bloqueados por Lockout de Cuenta: " << report.blockedByAccountLockout << "\r\n"
       << "    Latencia media defensiva impuesta: " << report.averageDefenseLatencyMs << " ms\r\n";
    LogSim(ss.str());
}

void OnRunStuffingSim() {
    LogSim(">>> Iniciando simulacion de Credential Stuffing (credenciales filtradas)...");

    std::vector<std::pair<std::string, std::string>> leakCombos = {
        {"leak_dump_1", "oldpass2020"},
        {"leak_dump_2", "spring2022"},
        {"leak_dump_3", "welcome123"},
        {"leak_dump_4", "qwertyuiop"},
        {"leak_dump_5", "secure_P@ssw0rd!2026"}
    };

    SecurityLab::AttackSimulator sim(g_server);
    auto report = sim.runCredentialStuffingSimulation("test_user_victim", leakCombos);

    for (const auto& ev : report.logEvents) {
        LogSim("    " + ev);
    }
    LogSim(">>> Fin de simulacion de Stuffing.\r\n");
}

void OnRunAudit() {
    SecurityLab::AccountSecurityProfile profile;
    profile.username = "cuenta_educativa_lab";
    profile.password = "Insta2024!";
    profile.mfaEnabled = (SendMessageA(g_hChkMfa, BM_GETCHECK, 0, 0) == BST_CHECKED);
    profile.passwordReusedAcrossServices = (SendMessageA(g_hChkReuse, BM_GETCHECK, 0, 0) == BST_CHECKED);
    profile.hasBackupRecoveryCodes = (SendMessageA(g_hChkBackup, BM_GETCHECK, 0, 0) == BST_CHECKED);
    profile.activeSessionsCount = 3;
    profile.hasVerifiedRecoveryEmail = true;
    profile.hasVerifiedRecoveryPhone = true;

    char mfaBuf[64];
    GetWindowTextA(g_hComboMfaType, mfaBuf, sizeof(mfaBuf));
    profile.mfaType = mfaBuf;

    auto report = g_auditor.generateAuditReport(profile);
    std::string md = g_auditor.exportReportToMarkdown(report);

    // Replace \n with \r\n for Windows EDIT control
    std::string winText;
    for (char c : md) {
        if (c == '\n') winText += "\r\n";
        else winText += c;
    }

    SetWindowTextA(g_hEditAuditOutput, winText.c_str());
}

void SwitchTab(int index) {
    ShowWindow(g_hPageAnalyzer, (index == 0) ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hPageSimulator, (index == 1) ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hPageAuditor, (index == 2) ? SW_SHOW : SW_HIDE);
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            HINSTANCE hInst = ((LPCREATESTRUCT)lParam)->hInstance;

            // Tab Control
            g_hTabCtrl = CreateWindowA(WC_TABCONTROLA, "", WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE,
                                       10, 10, 780, 520, hWnd, (HMENU)ID_TAB_CONTROL, hInst, NULL);

            TCITEMA tie;
            tie.mask = TCIF_TEXT;
            tie.pszText = (LPSTR)"1. Analizador de Seguridad";
            TabCtrl_InsertItem(g_hTabCtrl, 0, &tie);
            tie.pszText = (LPSTR)"2. Simulador de Ataques";
            TabCtrl_InsertItem(g_hTabCtrl, 1, &tie);
            tie.pszText = (LPSTR)"3. Auditor de Proteccion";
            TabCtrl_InsertItem(g_hTabCtrl, 2, &tie);

            // Create Sub-windows (pages)
            g_hPageAnalyzer = CreateWindowA("STATIC", "", WS_CHILD | WS_VISIBLE, 15, 40, 770, 480, hWnd, NULL, hInst, NULL);
            g_hPageSimulator = CreateWindowA("STATIC", "", WS_CHILD, 15, 40, 770, 480, hWnd, NULL, hInst, NULL);
            g_hPageAuditor = CreateWindowA("STATIC", "", WS_CHILD, 15, 40, 770, 480, hWnd, NULL, hInst, NULL);

            SetupAnalyzerTab(g_hPageAnalyzer, hInst);
            SetupSimulatorTab(g_hPageSimulator, hInst);
            SetupAuditorTab(g_hPageAuditor, hInst);

            SwitchTab(0);
            break;
        }
        case WM_NOTIFY: {
            LPNMHDR lpnmhdr = (LPNMHDR)lParam;
            if (lpnmhdr->idFrom == ID_TAB_CONTROL && lpnmhdr->code == TCN_SELCHANGE) {
                int curSel = TabCtrl_GetCurSel(g_hTabCtrl);
                SwitchTab(curSel);
            }
            break;
        }
        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            switch (wmId) {
                case ID_BTN_ANALYZE_PW:
                    OnAnalyzePassword();
                    break;
                case ID_BTN_RUN_BRUTE_FORCE:
                    OnRunBruteForceSim();
                    break;
                case ID_BTN_RUN_STUFFING:
                    OnRunStuffingSim();
                    break;
                case ID_BTN_RESET_SERVER:
                    g_server.resetState();
                    SetWindowTextA(g_hEditSimLogs, "[INFO] Servidor local reiniciado. Contadores de lockout y rate limit en cero.\r\n");
                    break;
                case ID_BTN_RUN_AUDIT:
                    OnRunAudit();
                    break;
            }
            break;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_TAB_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);

    WNDCLASSEXA wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "InstagramSecurityLabWndClass";

    if (!RegisterClassExA(&wc)) {
        return 1;
    }

    HWND hWnd = CreateWindowA(
        "InstagramSecurityLabWndClass",
        "Instagram Security Lab - Laboratorio de Ciberseguridad y Auditoria Defensiva (Local)",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 820, 580,
        NULL, NULL, hInstance, NULL
    );

    if (!hWnd) {
        return 1;
    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
