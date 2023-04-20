#pragma once

#include <iostream>
#include <stdarg.h>
#include <vector>
#include <AttestationClient.h>
#include <stdio.h>
#include <memory>
#include <mutex>
#include <fstream>
#include <sstream>
#include <ctime>
#include <chrono>
#include <iomanip>
#include <AttestationClient.h>
#include "Logger.h"

class Logger : public attest::AttestationLogger
{
public:
    Logger() {
        std::time_t time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::tm *local_time = std::localtime(&time);
        std::stringstream stream;
        stream << "TdxAttest-" << std::put_time(local_time,"%Y%m%d-%H%M%S") << ".log";
        log_filename = stream.str();
    }

    void Log(const char *log_tag,
             LogLevel level,
             const char *function,
             const int line,
             const char *fmt,
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

        std::stringstream stream;
        stream << "Level: " << attest::AttestationLogger::LogLevelStrings[level] << " Tag: " << log_tag << " "
               << function << ":" << line << ":" << &str[0] << std::endl;

        std::ofstream log_file(log_filename, std::ios_base::app);
        if (log_file) {
            log_file << stream.str();
            log_file.close();
        }
    }

private:
    std::string log_filename;
};