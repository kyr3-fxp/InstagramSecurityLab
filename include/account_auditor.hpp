#pragma once
#include "security_analyzer.hpp"
#include <string>
#include <vector>

namespace SecurityLab {

    struct AuditCheckItem {
        std::string category;
        std::string title;
        bool passed;
        std::string severity; // "LOW", "MEDIUM", "HIGH", "CRITICAL"
        std::string description;
        std::string remediation;
    };

    struct FullAuditReport {
        std::string targetIdentifier;
        int overallSecurityScore; // 0-100 (100 is best)
        std::string complianceStatus; // "Vulnerable", "Moderate", "Hardened"
        std::vector<AuditCheckItem> checklist;
        std::vector<std::string> immediateActionItems;
        std::string technicalSummary;
    };

    class AccountAuditor {
    public:
        AccountAuditor();
        FullAuditReport generateAuditReport(const AccountSecurityProfile& profile);
        std::string exportReportToMarkdown(const FullAuditReport& report);
    };

}
