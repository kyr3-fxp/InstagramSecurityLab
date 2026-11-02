#include "../include/security_analyzer.hpp"
#include <cmath>
#include <cctype>
#include <unordered_set>
#include <algorithm>

namespace SecurityLab {

    static const std::unordered_set<std::string> COMMON_WEAK_PASSWORDS = {
        "123456", "password", "12345678", "qwerty", "123456789", "12345",
        "1234", "111111", "1234567", "dragon", "welcome", "iloveyou",
        "instagram", "insta2024", "admin", "admin123", "secret", "princess",
        "pass1234", "password123", "instagram123", "letmein", "football"
    };

    SecurityAnalyzer::SecurityAnalyzer() {}

    double SecurityAnalyzer::calculateShannonEntropy(const std::string& str) {
        if (str.empty()) return 0.0;
        int counts[256] = {0};
        for (unsigned char c : str) {
            counts[c]++;
        }
        double entropy = 0.0;
        double len = static_cast<double>(str.length());
        for (int i = 0; i < 256; ++i) {
            if (counts[i] > 0) {
                double p = counts[i] / len;
                entropy -= p * (std::log(p) / std::log(2.0));
            }
        }
        return entropy * len; // Total entropy bits estimation
    }

    bool SecurityAnalyzer::checkCommonDictionary(const std::string& str) {
        std::string lower = str;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });
        return COMMON_WEAK_PASSWORDS.find(lower) != COMMON_WEAK_PASSWORDS.end();
    }

    bool SecurityAnalyzer::hasSequentialOrRepeatedChars(const std::string& str) {
        if (str.length() < 3) return false;
        int consecutive = 1;
        for (size_t i = 1; i < str.length(); ++i) {
            if (str[i] == str[i - 1] || str[i] == str[i - 1] + 1) {
                consecutive++;
                if (consecutive >= 3) return true;
            } else {
                consecutive = 1;
            }
        }
        return false;
    }

    PasswordAnalysisResult SecurityAnalyzer::analyzePassword(const std::string& password) {
        PasswordAnalysisResult res;
        res.password = password;
        res.hasUppercase = false;
        res.hasLowercase = false;
        res.hasDigits = false;
        res.hasSpecial = false;

        for (unsigned char c : password) {
            if (std::isupper(c)) res.hasUppercase = true;
            else if (std::islower(c)) res.hasLowercase = true;
            else if (std::isdigit(c)) res.hasDigits = true;
            else res.hasSpecial = true;
        }

        res.isCommonDictionary = checkCommonDictionary(password);
        res.hasRepetitivePatterns = hasSequentialOrRepeatedChars(password);
        res.entropyBits = calculateShannonEntropy(password);

        int score = 0;
        if (password.length() >= 8) score += 20;
        if (password.length() >= 12) score += 15;
        if (password.length() >= 16) score += 10;
        if (res.hasLowercase) score += 10;
        if (res.hasUppercase) score += 15;
        if (res.hasDigits) score += 15;
        if (res.hasSpecial) score += 15;

        if (res.isCommonDictionary) score -= 50;
        if (res.hasRepetitivePatterns) score -= 20;

        if (score < 0) score = 0;
        if (score > 100) score = 100;
        res.score = score;

        if (score < 30 || res.isCommonDictionary) {
            res.risk = RiskLevel::Critical;
        } else if (score < 60) {
            res.risk = RiskLevel::High;
        } else if (score < 80) {
            res.risk = RiskLevel::Medium;
        } else {
            res.risk = RiskLevel::Low;
        }

        if (password.length() < 8) {
            res.vulnerabilities.push_back("Longitud critica inferior a 8 caracteres (vulnerable a fuerza bruta instantánea).");
            res.recommendations.push_back("Aumentar la longitud mínima a al menos 14-16 caracteres o usar frase de paso (passphrase).");
        }
        if (res.isCommonDictionary) {
            res.vulnerabilities.push_back("Coincide con diccionarios de credenciales filtradas populares (SecLists/RockYou).");
            res.recommendations.push_back("Evitar palabras comunes o secuencias numéricas evidentes.");
        }
        if (res.hasRepetitivePatterns) {
            res.vulnerabilities.push_back("Contiene patrones repetitivos o secuencias alfanuméricas continuas.");
            res.recommendations.push_back("Eliminar patrones predecibles tipo '123' o 'aaa'.");
        }
        if (!res.hasSpecial || !res.hasUppercase) {
            res.recommendations.push_back("Incorporar diversidad de caracteres (mayúsculas, minúsculas, números y símbolos).");
        }

        return res;
    }

    int SecurityAnalyzer::calculateOverallRiskScore(const AccountSecurityProfile& profile, std::vector<std::string>& outRiskFactors) {
        int baseRisk = 0;

        auto pwAnalysis = analyzePassword(profile.password);
        if (pwAnalysis.risk == RiskLevel::Critical) {
            baseRisk += 40;
            outRiskFactors.push_back("Contraseña extremadamente débil o presente en listas públicas.");
        } else if (pwAnalysis.risk == RiskLevel::High) {
            baseRisk += 25;
            outRiskFactors.push_back("Contraseña de baja complejidad.");
        }

        if (profile.passwordReusedAcrossServices) {
            baseRisk += 30;
            outRiskFactors.push_back("Reutilización de contraseña detectada (Riesgo alto de Credential Stuffing).");
        }

        if (!profile.mfaEnabled || profile.mfaType == "None") {
            baseRisk += 35;
            outRiskFactors.push_back("Sin autenticación en dos pasos (2FA inactivo).");
        } else if (profile.mfaType == "SMS") {
            baseRisk += 10;
            outRiskFactors.push_back("2FA basado en SMS es vulnerable a SIM Swapping e intercepción SS7.");
        }

        if (profile.activeSessionsCount > 3) {
            baseRisk += 15;
            outRiskFactors.push_back("Múltiples sesiones concurrentes activas (superficie de ataque de secuestro de tokens).");
        }

        if (!profile.hasBackupRecoveryCodes) {
            baseRisk += 10;
            outRiskFactors.push_back("Ausencia de códigos de recuperación de respaldo offline.");
        }

        if (baseRisk > 100) baseRisk = 100;
        return baseRisk;
    }

    std::string SecurityAnalyzer::riskLevelToString(RiskLevel level) {
        switch (level) {
            case RiskLevel::Low: return "BAJO (Protegido)";
            case RiskLevel::Medium: return "MEDIO (Atención requerida)";
            case RiskLevel::High: return "ALTO (Vulnerable)";
            case RiskLevel::Critical: return "CRÍTICO (Exposición inminente)";
            default: return "DESCONOCIDO";
        }
    }

}
