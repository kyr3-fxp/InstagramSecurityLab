#include "../include/account_auditor.hpp"
#include <sstream>
#include <iomanip>

namespace SecurityLab {

    AccountAuditor::AccountAuditor() {}

    FullAuditReport AccountAuditor::generateAuditReport(const AccountSecurityProfile& profile) {
        FullAuditReport report;
        report.targetIdentifier = profile.username;

        SecurityAnalyzer analyzer;
        auto pwRes = analyzer.analyzePassword(profile.password);

        int score = 100;

        // 1. Password Strength Check
        AuditCheckItem c1;
        c1.category = "Autenticación Básica";
        c1.title = "Complejidad y Entropía de Contraseña";
        if (pwRes.risk == RiskLevel::Low) {
            c1.passed = true;
            c1.severity = "LOW";
            c1.description = "La contraseña posee alta entropía (" + std::to_string(static_cast<int>(pwRes.entropyBits)) + " bits) y no coincide con patrones comunes.";
            c1.remediation = "Mantener la contraseña actual en un gestor de contraseñas seguro.";
        } else if (pwRes.risk == RiskLevel::Medium) {
            c1.passed = false;
            c1.severity = "MEDIUM";
            c1.description = "Entropía intermedia. Requiere mayor robustez.";
            c1.remediation = "Incrementar longitud a 14+ caracteres.";
            score -= 15;
        } else {
            c1.passed = false;
            c1.severity = "CRITICAL";
            c1.description = "Contraseña débil o contenida en diccionarios de filtraciones conocidas.";
            c1.remediation = "Cambio inmediato de contraseña por una frase de paso (passphrase) aleatoria.";
            score -= 35;
        }
        report.checklist.push_back(c1);

        // 2. Password Reuse Check
        AuditCheckItem c2;
        c2.category = "Gestión de Credenciales";
        c2.title = "Aislamiento de Contraseña (Reutilización)";
        if (!profile.passwordReusedAcrossServices) {
            c2.passed = true;
            c2.severity = "LOW";
            c2.description = "No se detecta reutilización en plataformas externas.";
            c2.remediation = "Ninguna acción necesaria.";
        } else {
            c2.passed = false;
            c2.severity = "HIGH";
            c2.description = "La misma contraseña se usa en otros servicios web, exponiendo la cuenta a 'Credential Stuffing'.";
            c2.remediation = "Generar una contraseña única exclusiva para esta plataforma.";
            score -= 25;
            report.immediateActionItems.push_back("Disociar contraseña: No compartir la misma clave entre redes sociales y correos.");
        }
        report.checklist.push_back(c2);

        // 3. Multi-Factor Authentication (MFA)
        AuditCheckItem c3;
        c3.category = "Defensa en Profundidad";
        c3.title = "Autenticación de Dos Factores (2FA)";
        if (profile.mfaEnabled) {
            if (profile.mfaType == "SecurityKey_FIDO2" || profile.mfaType == "TOTP_Authenticator") {
                c3.passed = true;
                c3.severity = "LOW";
                c3.description = "2FA habilitado mediante App de Autenticación (TOTP) o llave física FIDO2/WebAuthn.";
                c3.remediation = "Mantener dispositivos sincronizados y llaves registradas.";
            } else {
                c3.passed = true;
                c3.severity = "MEDIUM";
                c3.description = "2FA habilitado por SMS (Vulnerable a ataques de ingeniería social / SIM Swapping).";
                c3.remediation = "Migrar de SMS a Google Authenticator, Aegis o llave de hardware FIDO2.";
                score -= 10;
                report.immediateActionItems.push_back("Migrar 2FA de SMS a aplicación TOTP (Google Authenticator / Aegis).");
            }
        } else {
            c3.passed = false;
            c3.severity = "CRITICAL";
            c3.description = "2FA Desactivado. La cuenta está protegida por un único vector de autenticación.";
            c3.remediation = "Activar 2FA inmediatamente en Configuración > Centro de Cuentas > Contraseña y Seguridad.";
            score -= 35;
            report.immediateActionItems.push_back("Activar Autenticación en Dos Pasos (2FA) de forma obligatoria.");
        }
        report.checklist.push_back(c3);

        // 4. Session and Device Hygiene
        AuditCheckItem c4;
        c4.category = "Higiene de Sesiones";
        c4.title = "Sesiones Activas Concurrentes";
        if (profile.activeSessionsCount <= 2) {
            c4.passed = true;
            c4.severity = "LOW";
            c4.description = "Número reducido de sesiones concurrentes (" + std::to_string(profile.activeSessionsCount) + ").";
            c4.remediation = "Monitorear periódicamente los inicios de sesión.";
        } else {
            c4.passed = false;
            c4.severity = "MEDIUM";
            c4.description = "Se detectan " + std::to_string(profile.activeSessionsCount) + " sesiones activas simultáneamente.";
            c4.remediation = "Cerrar sesiones en dispositivos obsoletos o no reconocidos en 'Dónde has iniciado sesión'.";
            score -= 10;
            report.immediateActionItems.push_back("Revocar todas las sesiones desconocidas en 'Dónde has iniciado sesión'.");
        }
        report.checklist.push_back(c4);

        // 5. Recovery Mechanisms
        AuditCheckItem c5;
        c5.category = "Recuperación y Resiliencia";
        c5.title = "Canales de Recuperación y Códigos de Respaldo";
        if (profile.hasBackupRecoveryCodes && profile.hasVerifiedRecoveryEmail) {
            c5.passed = true;
            c5.severity = "LOW";
            c5.description = "Canales redundantes configurados: Códigos de reserva offline y correo verificado.";
            c5.remediation = "Almacenar los códigos de recuperación impresos o en una bóveda cifrada.";
        } else {
            c5.passed = false;
            c5.severity = "HIGH";
            c5.description = "Faltan códigos de respaldo descargados o verificación de correo de recuperación.";
            c5.remediation = "Generar y guardar los 8 códigos de recuperación de respaldo de Instagram.";
            score -= 15;
            report.immediateActionItems.push_back("Descargar los códigos de recuperación de respaldo y guardarlos en lugar seguro.");
        }
        report.checklist.push_back(c5);

        if (score < 0) score = 0;
        report.overallSecurityScore = score;

        if (score >= 85) {
            report.complianceStatus = "HARDENED (Robusto / Nivel Defensivo Óptimo)";
        } else if (score >= 60) {
            report.complianceStatus = "MODERATE (Aceptable con Brechas Identificadas)";
        } else {
            report.complianceStatus = "VULNERABLE (Alto Riesgo de Compromiso)";
        }

        std::ostringstream ss;
        ss << "Puntaje de Seguridad: " << score << "/100 - Estado: " << report.complianceStatus << "\n";
        ss << "Total de comprobaciones realizadas: " << report.checklist.size() << "\n";
        report.technicalSummary = ss.str();

        return report;
    }

    std::string AccountAuditor::exportReportToMarkdown(const FullAuditReport& report) {
        std::ostringstream ss;
        ss << "# INFORME DE AUDITORÍA DE SEGURIDAD DEFENSIVA\n\n";
        ss << "**Objetivo analizado:** @" << report.targetIdentifier << "\n";
        ss << "**Puntuación de Seguridad:** `" << report.overallSecurityScore << "/100`\n";
        ss << "**Diagnóstico Global:** " << report.complianceStatus << "\n\n";

        ss << "## 1. Verificaciones del Laboratorio\n\n";
        ss << "| Categoría | Control de Seguridad | Estado | Severidad | Remediación |\n";
        ss << "|---|---|---|---|---|\n";
        for (const auto& item : report.checklist) {
            ss << "| " << item.category << " | " << item.title << " | "
               << (item.passed ? "✅ Aprobado" : "❌ Deficiencia") << " | "
               << item.severity << " | " << item.remediation << " |\n";
        }

        if (!report.immediateActionItems.empty()) {
            ss << "\n## 2. Plan de Acción Inmediato (Mitigación)\n\n";
            for (size_t i = 0; i < report.immediateActionItems.size(); ++i) {
                ss << (i + 1) << ". " << report.immediateActionItems[i] << "\n";
            }
        }

        return ss.str();
    }

}
