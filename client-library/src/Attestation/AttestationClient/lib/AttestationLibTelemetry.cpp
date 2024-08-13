#include "AttestationLibTelemetry.h"

namespace attest {
    std::shared_ptr<TelemetryReportingBase> telemetry_reporting;
    void SetTelemetryReporting(const std::shared_ptr<TelemetryReportingBase> telemetry_reporting_) {
        if (attest::telemetry_reporting.get() == nullptr) {
            attest::telemetry_reporting = telemetry_reporting_;
        }
    }
}