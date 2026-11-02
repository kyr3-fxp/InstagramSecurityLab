#include "../include/auth_simulator.hpp"
#include <thread>
#include <sstream>
#include <iomanip>

namespace SecurityLab {

    LocalMockAuthServer::LocalMockAuthServer() {
        // Cuentas de laboratorio por defecto
        registerAccount("test_user_victim", "secure_P@ssw0rd!2026", true);
        registerAccount("test_weak_account", "123456", false);
    }

    void LocalMockAuthServer::configure(const RateLimitConfig& config) {
        config_ = config;
    }

    void LocalMockAuthServer::registerAccount(const std::string& username, const std::string& correctPassword, bool mfaEnabled) {
        AccountData acc;
        acc.passwordHash = correctPassword; // En laboratorio local educativo usamos comparación directa
        acc.mfaEnabled = mfaEnabled;
        acc.consecutiveFailures = 0;
        acc.lockedUntil = std::chrono::system_clock::time_point::min();
        accounts_[username] = acc;
    }

    void LocalMockAuthServer::resetState() {
        for (auto& pair : accounts_) {
            pair.second.consecutiveFailures = 0;
            pair.second.lockedUntil = std::chrono::system_clock::time_point::min();
        }
        ipRecords_.clear();
        logs_.clear();
    }

    int LocalMockAuthServer::getFailedAttemptsCount(const std::string& username) {
        auto it = accounts_.find(username);
        return (it != accounts_.end()) ? it->second.consecutiveFailures : 0;
    }

    bool LocalMockAuthServer::isAccountLocked(const std::string& username) {
        auto it = accounts_.find(username);
        if (it == accounts_.end()) return false;
        auto now = std::chrono::system_clock::now();
        return now < it->second.lockedUntil;
    }

    const std::vector<LoginAttempt>& LocalMockAuthServer::getAuditLogs() const {
        return logs_;
    }

    AuthResultStatus LocalMockAuthServer::processLogin(
        const std::string& username,
        const std::string& password,
        const std::string& clientIp,
        const std::string& userAgent,
        int& outDelayMs,
        std::string& outMessage
    ) {
        auto now = std::chrono::system_clock::now();
        outDelayMs = 0;

        // 1. Detección de Rate Limiting por Ventana Deslizante (IP)
        auto& ipTracker = ipRecords_[clientIp];
        auto windowCutoff = now - std::chrono::seconds(config_.windowSeconds);
        std::vector<std::chrono::system_clock::time_point> validTimestamps;
        for (const auto& t : ipTracker.attempts) {
            if (t >= windowCutoff) {
                validTimestamps.push_back(t);
            }
        }
        ipTracker.attempts = validTimestamps;

        if (static_cast<int>(ipTracker.attempts.size()) >= config_.maxAttemptsPerWindow) {
            outMessage = "429 Too Many Requests: Límite de tasa excedido para la dirección IP: " + clientIp;
            outDelayMs = 1500;
            logs_.push_back({clientIp, userAgent, password, now, false, "RATE_LIMITED", outDelayMs});
            return AuthResultStatus::RateLimited;
        }

        ipTracker.attempts.push_back(now);

        // 2. Verificación de existencia de cuenta
        auto accIt = accounts_.find(username);
        if (accIt == accounts_.end()) {
            outMessage = "401 Unauthorized: Credenciales incorrectas.";
            outDelayMs = config_.baseDelayMs;
            logs_.push_back({clientIp, userAgent, password, now, false, "USER_NOT_FOUND", outDelayMs});
            return AuthResultStatus::InvalidCredentials;
        }

        AccountData& acc = accIt->second;

        // 3. Verificación de bloqueo de cuenta (Lockout)
        if (now < acc.lockedUntil) {
            auto remainingSeconds = std::chrono::duration_cast<std::chrono::seconds>(acc.lockedUntil - now).count();
            outMessage = "403 Forbidden: Cuenta temporalmente bloqueada por actividad sospechosa. Restante: " +
                         std::to_string(remainingSeconds) + "s.";
            outDelayMs = 1000;
            logs_.push_back({clientIp, userAgent, password, now, false, "ACCOUNT_LOCKED", outDelayMs});
            return AuthResultStatus::AccountLockedOut;
        }

        // 4. Aplicación de Progressive Delay (Backoff artificial)
        if (config_.enableProgressiveDelay && acc.consecutiveFailures > 0) {
            outDelayMs = config_.baseDelayMs * (1 << std::min(acc.consecutiveFailures, 5));
        } else {
            outDelayMs = config_.baseDelayMs;
        }

        // 5. Comparación de credenciales
        if (acc.passwordHash != password) {
            acc.consecutiveFailures++;

            if (acc.consecutiveFailures >= config_.lockoutThreshold) {
                acc.lockedUntil = now + std::chrono::seconds(config_.lockoutDurationSeconds);
                outMessage = "403 Forbidden: Umbral de intentos fallidos alcanzado (" +
                             std::to_string(acc.consecutiveFailures) + "). Cuenta bloqueada por " +
                             std::to_string(config_.lockoutDurationSeconds) + " segundos.";
                logs_.push_back({clientIp, userAgent, password, now, false, "LOCKOUT_TRIGGERED", outDelayMs});
                return AuthResultStatus::AccountLockedOut;
            }

            outMessage = "401 Unauthorized: Contraseña incorrecta. Intento fallido " +
                         std::to_string(acc.consecutiveFailures) + "/" +
                         std::to_string(config_.lockoutThreshold);
            logs_.push_back({clientIp, userAgent, password, now, false, "INVALID_PASSWORD", outDelayMs});
            return AuthResultStatus::InvalidCredentials;
        }

        // 6. Éxito y flujo 2FA
        acc.consecutiveFailures = 0;
        if (acc.mfaEnabled) {
            outMessage = "200 Partial Auth: Credenciales válidas. Se requiere código de segundo factor (MFA/2FA).";
            logs_.push_back({clientIp, userAgent, password, now, true, "MFA_CHALLENGE_ISSUED", outDelayMs});
            return AuthResultStatus::MfaRequired;
        }

        outMessage = "200 OK: Autenticación exitosa. Token de sesión generado.";
        logs_.push_back({clientIp, userAgent, password, now, true, "SUCCESS", outDelayMs});
        return AuthResultStatus::Success;
    }

    // --- Implementación de AttackSimulator ---

    AttackSimulator::AttackSimulator(LocalMockAuthServer& server) : server_(server) {}

    AttackSimulationReport AttackSimulator::runBruteForceSimulation(
        const std::string& targetUser,
        const std::vector<std::string>& wordlist,
        const std::string& clientIp
    ) {
        AttackSimulationReport report = {0, 0, 0, 0, 0, 0.0, {}};
        long long totalLatency = 0;

        for (const auto& candidate : wordlist) {
            report.totalAttempts++;
            int delayMs = 0;
            std::string msg;

            AuthResultStatus res = server_.processLogin(
                targetUser, candidate, clientIp, "Educational-Simulated-Agent/1.0", delayMs, msg
            );
            totalLatency += delayMs;

            std::ostringstream ss;
            ss << "[Intento #" << report.totalAttempts << "] Pass: '" << candidate << "' -> ";

            switch (res) {
                case AuthResultStatus::Success:
                    report.successfulLogins++;
                    ss << "[ÉXITO] Sesión creada.";
                    break;
                case AuthResultStatus::MfaRequired:
                    report.successfulLogins++;
                    ss << "[PARCIAL] Clave correcta, pero DETENIDO por 2FA.";
                    break;
                case AuthResultStatus::RateLimited:
                    report.blockedByRateLimit++;
                    ss << "[BLOQUEO IP] Tasa de peticiones excedida.";
                    break;
                case AuthResultStatus::AccountLockedOut:
                    report.blockedByAccountLockout++;
                    ss << "[BLOQUEO CUENTA] Cuenta bloqueada por protección.";
                    break;
                case AuthResultStatus::InvalidCredentials:
                default:
                    ss << "[FALLO] Credencial inválida (Penalización: " << delayMs << "ms).";
                    break;
            }
            report.logEvents.push_back(ss.str());

            // Detener si la cuenta se bloquea o si ya tuvo éxito
            if (res == AuthResultStatus::Success || res == AuthResultStatus::AccountLockedOut) {
                break;
            }
        }

        if (report.totalAttempts > 0) {
            report.averageDefenseLatencyMs = static_cast<double>(totalLatency) / report.totalAttempts;
        }
        return report;
    }

    AttackSimulationReport AttackSimulator::runCredentialStuffingSimulation(
        const std::string& targetUser,
        const std::vector<std::pair<std::string, std::string>>& leakComboList
    ) {
        AttackSimulationReport report = {0, 0, 0, 0, 0, 0.0, {}};
        long long totalLatency = 0;

        int fakeIpSubnet = 10;
        for (const auto& combo : leakComboList) {
            report.totalAttempts++;
            std::string rotatingIp = "192.168.1." + std::to_string(fakeIpSubnet++);
            int delayMs = 0;
            std::string msg;

            AuthResultStatus res = server_.processLogin(
                targetUser, combo.second, rotatingIp, "Python-requests/2.28 (Simulated)", delayMs, msg
            );
            totalLatency += delayMs;

            std::ostringstream ss;
            ss << "[Stuffing " << rotatingIp << "] Credencial filtrada '" << combo.second << "' -> ";
            if (res == AuthResultStatus::Success || res == AuthResultStatus::MfaRequired) {
                report.successfulLogins++;
                ss << (res == AuthResultStatus::MfaRequired ? "[MITIGADO POR 2FA]" : "[COMPROMETIDA]");
                report.logEvents.push_back(ss.str());
                break;
            } else if (res == AuthResultStatus::AccountLockedOut) {
                report.blockedByAccountLockout++;
                ss << "[DEFENSA ACTIVA: Cuenta Bloqueada Globalmente]";
                report.logEvents.push_back(ss.str());
                break;
            } else {
                ss << "[FALLO DE REUTILIZACIÓN]";
            }
            report.logEvents.push_back(ss.str());
        }

        if (report.totalAttempts > 0) {
            report.averageDefenseLatencyMs = static_cast<double>(totalLatency) / report.totalAttempts;
        }
        return report;
    }

    AttackSimulationReport AttackSimulator::runDistributedSpraySimulation(
        const std::vector<std::string>& targetUsers,
        const std::string& commonPassword
    ) {
        AttackSimulationReport report = {0, 0, 0, 0, 0, 0.0, {}};
        long long totalLatency = 0;

        int ipCounter = 100;
        for (const auto& user : targetUsers) {
            report.totalAttempts++;
            std::string distributedIp = "10.0.0." + std::to_string(ipCounter++);
            int delayMs = 0;
            std::string msg;

            AuthResultStatus res = server_.processLogin(
                user, commonPassword, distributedIp, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", delayMs, msg
            );
            totalLatency += delayMs;

            std::ostringstream ss;
            ss << "[Spray sobre @" << user << " con '" << commonPassword << "'] -> ";
            if (res == AuthResultStatus::Success) {
                report.successfulLogins++;
                ss << "[VULNERABLE: Clave común coincide]";
            } else if (res == AuthResultStatus::MfaRequired) {
                report.successfulLogins++;
                ss << "[RESISTENTE: Detenido por 2FA]";
            } else {
                ss << "[DEFENDIDO: Intento no coincidente]";
            }
            report.logEvents.push_back(ss.str());
        }

        if (report.totalAttempts > 0) {
            report.averageDefenseLatencyMs = static_cast<double>(totalLatency) / report.totalAttempts;
        }
        return report;
    }

}
