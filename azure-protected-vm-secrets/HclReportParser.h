#include "SnpVmReport.h"
#include <memory>
#include <vector>

class HclReportParser {
public:
    bool IsValidHclReport(const std::vector<unsigned char>& hclReport) const;
};
