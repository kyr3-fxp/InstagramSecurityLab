#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>

namespace SecurityLab {

    enum class AuthResultStatus {
        Success,
        InvalidCredentials,
        RateLimited,
        AccountLockedOut,
        SuspiciousActivityBlocked,
        MfaRequired
    };

    struct LoginAttempt {
        std::string ipAddress;
        std::string userAgent;
        std::string attemptedPassword;
        std::chrono::system_clock::time_point timestamp;
        bool successful;
        std::string responseReason;
        int delayAppliedMs;
    };

    struct RateLimitConfig {
        int maxAttemptsPerWindow = 5;       // e.g. 5 attempts
        int windowSeconds = 60;             // per 60 seconds per IP
        int lockoutThreshold = 7;           // Lockout account after 7 consecutive failures
        int lockoutDurationSeconds = 300;   // 5 minutes lockout
        bool enableProgressiveDelay = true; // Exponential / progressive backoff
        int baseDelayMs = 200;              // Base artificial latency
    };

    class LocalMockAuthServer {
    public:
        LocalMockAuthServer();
        void configure(const RateLimitConfig& config);
        void registerAccount(const std::string& username, const std::string& correctPassword, bool mfaEnabled = false);
        
        AuthResultStatus processLogin(
            const std::string& username,
            const std::string& password,
            const std::string& clientIp,
            const std::string& userAgent,
            int& outDelayMs,
            std::string& outMessage
        );

        void resetState();
        int getFailedAttemptsCount(const std::string& username);
        bool isAccountLocked(const std::string& username);
        const std::vector<LoginAttempt>& getAuditLogs() const;

    private:
        RateLimitConfig config_;

        struct AccountData {
            std::string passwordHash;
            bool mfaEnabled;
            int consecutiveFailures;
            std::chrono::system_clock::time_point lockedUntil;
        };

        struct IpTracker {
            std::vector<std::chrono::system_clock::time_point> attempts;
        };

        std::unordered_map<std::string, AccountData> accounts_;
        std::unordered_map<std::string, IpTracker> ipRecords_;
        std::vector<LoginAttempt> logs_;
    };

    struct AttackSimulationReport {
        int totalAttempts;
        int successfulLogins;
        int blockedByRateLimit;
        int blockedByAccountLockout;
        int blockedByAnomalyDetection;
        double averageDefenseLatencyMs;
        std::vector<std::string> logEvents;
    };

    class AttackSimulator {
    public:
        explicit AttackSimulator(LocalMockAuthServer& server);

        AttackSimulationReport runBruteForceSimulation(
            const std::string& targetUser,
            const std::vector<std::string>& wordlist,
            const std::string& clientIp
        );

        AttackSimulationReport runCredentialStuffingSimulation(
            const std::string& targetUser,
            const std::vector<std::pair<std::string, std::string>>& leakComboList
        );

        AttackSimulationReport runDistributedSpraySimulation(
            const std::vector<std::string>& targetUsers,
            const std::string& commonPassword
        );

    private:
        LocalMockAuthServer& server_;
    };

}
