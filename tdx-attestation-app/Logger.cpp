#include <iostream>
#include <stdarg.h>
#include <vector>
#include <AttestationClient.h>
#include <iostream>
#include "Logger.h"

void Logger::Log(const char* log_tag,
    LogLevel level,
    const char* function,
    const int line,
    const char* fmt,
    ...) {
    va_list args;
    va_start(args, fmt);
    size_t len = std::vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    std::vector<char> str(len + 1);

    va_start(args, fmt);
    std::vsnprintf(&str[0], len + 1, fmt, args);
    va_end(args);

    // Print Logs, comment and recompilte to suppress logs
    printf("Level: %s Tag: %s %s:%d:%s\n", attest::AttestationLogger::LogLevelStrings[level].c_str(), log_tag, function, line, &str[0]);
}