//-------------------------------------------------------------------------------------------------
// <copyright file="Logging.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#pragma once

#include <stdio.h>
#include <stdarg.h>
#include <memory>
#include "AttestationLogger.h"

namespace attest {

extern std::shared_ptr<AttestationLogger> logger;

/**
 * @brief This function will be used to set the Logger handle that will be used
 * by the client lib for logging.
 * @param[in] logger share_ptr object of AttestationLogger.
 */
void SetLogger(const std::shared_ptr<AttestationLogger>& logger);

} // attest

using namespace attest;

#ifndef LOG_TAG
#define LOG_TAG "AttestatationClientLib"
#endif

#define CLIENT_LOG_ERROR(...) if(logger.get() != nullptr) logger->Log(LOG_TAG, \
                                                                      AttestationLogger::Error, \
                                                                      __FUNCTION__, \
                                                                      __LINE__, \
                                                                      __VA_ARGS__)

#define CLIENT_LOG_WARN(...) if(logger.get() != nullptr) logger->Log(LOG_TAG, \
                                                                     AttestationLogger::Warn, \
                                                                     __FUNCTION__, \
                                                                     __LINE__, \
                                                                     __VA_ARGS__)

#define CLIENT_LOG_INFO(...) if(logger.get() != nullptr) logger->Log(LOG_TAG, \
                                                                     AttestationLogger::Info, \
                                                                     __FUNCTION__, \
                                                                     __LINE__, \
                                                                     __VA_ARGS__)

#define CLIENT_LOG_DEBUG(...) if(logger.get() != nullptr) logger->Log(LOG_TAG, \
                                                                      AttestationLogger::Debug, \
                                                                      __FUNCTION__, \
                                                                      __LINE__, \
                                                                      __VA_ARGS__)
