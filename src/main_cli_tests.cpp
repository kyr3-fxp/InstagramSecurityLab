#include <iostream>
#include <cassert>
#include "../include/security_analyzer.hpp"
#include "../include/auth_simulator.hpp"
#include "../include/account_auditor.hpp"

int main() {
    std::cout << "========================================================\n";
    std::cout << "   INSTAGRAM SECURITY LAB - SUITE DE PRUEBAS DEFENSIVAS  \n";
    std::cout << "========================================================\n\n";

    // 1. Test Analizador de Seguridad
    std::cout << "[*] 1. Ejecutando pruebas unitarias de SecurityAnalyzer...\n";
    SecurityLab::SecurityAnalyzer analyzer;

    auto weakRes = analyzer.analyzePassword("123456");
    assert(weakRes.risk == SecurityLab::RiskLevel::Critical);
    assert(weakRes.isCommonDictionary == true);
    std::cout << "    [+] Contrasena debil detectada correctamente (Score: " << weakRes.score << "/100)\n";

    auto strongRes = analyzer.analyzePassword("K9#vP2$xL!90@qZ7&m");
    assert(strongRes.risk == SecurityLab::RiskLevel::Low);
    assert(strongRes.score >= 80);
    std::cout << "    [+] Contrasena robusta aprobada con alta entropia: " << strongRes.entropyBits << " bits.\n";

    // 2. Test Servidor Local y Simulador
    std::cout << "\n[*] 2. Ejecutando simulaciones con LocalMockAuthServer...\n";
    SecurityLab::LocalMockAuthServer server;
    SecurityLab::RateLimitConfig cfg;
    cfg.maxAttemptsPerWindow = 3; // Ventana estricta para el test
    cfg.lockoutThreshold = 4;
    cfg.windowSeconds = 10;
    server.configure(cfg);

    int delay = 0;
    std::string msg;

    // Intento 1, 2, 3: fallos normales
    server.processLogin("test_user_victim", "bad_pass_1", "10.0.0.1", "curl/7.68", delay, msg);
    server.processLogin("test_user_victim", "bad_pass_2", "10.0.0.1", "curl/7.68", delay, msg);
    server.processLogin("test_user_victim", "bad_pass_3", "10.0.0.1", "curl/7.68", delay, msg);

    // Intento 4: Debe disparar Rate Limit por IP
    auto res4 = server.processLogin("test_user_victim", "bad_pass_4", "10.0.0.1", "curl/7.68", delay, msg);
    assert(res4 == SecurityLab::AuthResultStatus::RateLimited);
    std::cout << "    [+] Rate Limiting activo y verificado: " << msg << "\n";

    // 3. Test Auditor de Cuenta
    std::cout << "\n[*] 3. Ejecutando auditoria con AccountAuditor...\n";
    SecurityLab::AccountAuditor auditor;
    SecurityLab::AccountSecurityProfile profile;
    profile.username = "demo_audit_target";
    profile.password = "MyComplexPassword2026!";
    profile.mfaEnabled = true;
    profile.mfaType = "TOTP_Authenticator";
    profile.passwordReusedAcrossServices = false;
    profile.activeSessionsCount = 1;
    profile.hasBackupRecoveryCodes = true;
    profile.hasVerifiedRecoveryEmail = true;
    profile.hasVerifiedRecoveryPhone = true;

    auto auditReport = auditor.generateAuditReport(profile);
    std::cout << "    [+] Puntaje de seguridad obtenido: " << auditReport.overallSecurityScore << "/100\n";
    std::cout << "    [+] Estado de cumplimiento: " << auditReport.complianceStatus << "\n";
    assert(auditReport.overallSecurityScore >= 85);

    std::cout << "\n========================================================\n";
    std::cout << "  [TODAS LAS PRUEBAS COMPLETADAS CON EXITO DEFENSORES]   \n";
    std::cout << "========================================================\n";
    return 0;
}
