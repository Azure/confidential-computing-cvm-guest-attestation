//-------------------------------------------------------------------------------------------------
// <copyright file="NativeConverter.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <string>
#include "TpmUnseal.h"

namespace attest {

/**
 * @brief This function will be used to map a string to its equivalent enum value in
 * enum BlockCipherMode.
 * @param[in] mode_str std::string to be mapped to the enum value.
 * @param[out] mode The enum value that is equivalen to the input string.
 * @return True if the string can be mapped to an emum value. False otherwise.
 */
bool toNative(const std::string& mode_str,
              BlockCipherMode& mode);

/**
 * @brief This function will be used to map a string to its equivalent enum value in
 * enum BlockCipherPadding.
 * @param[in] padding_str std::string to be mapped to the enum value.
 * @param[out] padding The enum value that is equivalen to the input string.
 * @return True if the string can be mapped to an emum value. False otherwise.
 */
bool toNative(const std::string& padding_str,
              BlockCipherPadding& padding);

/**
 * @brief This function will be used to map a string to its equivalent enum value in
 * enum CipherAlgorithm.
 * @param[in] cipher_str std::string to be mapped to the enum value.
 * @param[out] cipher The enum value that is equivalen to the input string.
 * @return True if the string can be mapped to an emum value. False otherwise.
 */
bool toNative(const std::string& cipher_str,
              CipherAlgorithm& cipher);
}// attest