#pragma once
#include <string>
#include <vector>

namespace SecurityLab {

    enum class RiskLevel {
        Low,
        Medium,
        High,
        Critical
    };

    struct PasswordAnalysisResult {
        std::string password;
        double entropyBits;
        int score; // 0 - 100
        RiskLevel risk;
        bool hasUppercase;
        bool hasLowercase;
        bool hasDigits;
        bool hasSpecial;
        bool isCommonDictionary;
        bool hasRepetitivePatterns;
        std::vector<std::string> vulnerabilities;
        std::vector<std::string> recommendations;
    };

    struct AccountSecurityProfile {
        std::string username;
        std::string password;
        bool mfaEnabled;
        std::string mfaType; // "None", "SMS", "TOTP_Authenticator", "SecurityKey_FIDO2"
        bool passwordReusedAcrossServices;
        int activeSessionsCount;
        bool hasBackupRecoveryCodes;
        bool hasVerifiedRecoveryEmail;
        bool hasVerifiedRecoveryPhone;
    };

    class SecurityAnalyzer {
    public:
        SecurityAnalyzer();
        
        PasswordAnalysisResult analyzePassword(const std::string& password);
        int calculateOverallRiskScore(const AccountSecurityProfile& profile, std::vector<std::string>& outRiskFactors);
        static std::string riskLevelToString(RiskLevel level);

    private:
        double calculateShannonEntropy(const std::string& str);
        bool checkCommonDictionary(const std::string& str);
        bool hasSequentialOrRepeatedChars(const std::string& str);
    };

}
