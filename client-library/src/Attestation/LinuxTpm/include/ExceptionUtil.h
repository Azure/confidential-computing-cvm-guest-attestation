#pragma once

#include <string>
#include <system_error>
#include <vector>

#ifndef PLATFORM_UNIX
#include <winerror.h>

/// <summary>
/// Exception object which wraps up a Windows API error code.
/// </summary>
class HResultException : public std::system_error
{
public:

    /// <summary>
    /// Wrapper for NTSTATUS error code.
    /// </summary>
    /// <param name="status">NTSTATUS error code</param>
    /// <param name="desc">Error description</param>
    static void ThrowOnNtError(long status,
                               const char* desc = "NTSTATUS error")
    {
        if (0 != status)
        {
            throw HResultException(HRESULT_FROM_NT(status), desc);
        }
    }

    /// <summary>
    /// Wrapper for HRESULT error code.
    /// </summary>
    /// <param name="hr">HRESULT error code</param>
    /// <param name="desc">Error description</param>
    static void ThrowOnHResultError(HRESULT hr,
                                    const char* desc = HRESULT_DEFAULT_DESC)
    {
        if (FAILED(hr))
        {
            throw HResultException(hr, desc);
        }
    }

    /// <summary>
    /// HResult Constructor
    /// </summary>
    /// <param name="hr">HRESULT error code</param>
    /// <param name="desc">Error description</param>
    HResultException(HRESULT hr, const std::string& desc) :
        std::system_error(std::error_code(hr, std::generic_category()))
    {
        this->hr = hr;
        this->description = desc + ':' + std::to_string(hr);
    }

    HResultException(HRESULT hr) : HResultException(hr, HRESULT_DEFAULT_DESC) {}

    /// <summary>
    /// Helper function to return HRESULT error
    /// </summary>
    /// <returns>HRESULT error code</returns>
    HRESULT Result() const { return hr; }

    /// <summary>
    /// Helper function to return error description
    /// </summary>
    /// <returns>Error description</returns>
    const char* what() const override { return description.c_str(); }

private:
    static constexpr char* HRESULT_DEFAULT_DESC = const_cast<char* const> ("HRESULT error");
    HRESULT hr;
    std::string description;
};

#endif

#include <openssl/evp.h>

// This macro indirection is required to expand x and convert it to a string.
// TOSTRING expands the macro to whatever value it is returns as, and
// __STRIGIFY_MACRO convers x to a string.
#define __STRINGIFY_MACRO(x) #x
#define TOSTRING(x) __STRINGIFY_MACRO(x)

/**
 * Throws the result of ERR_get_error as an OpenSslException. Also contains file
 * and line number information
 */
#define THROW_LAST_OPENSSL_ERROR(__ret) \
    do { \
        std::string __s(ERR_error_string(ERR_get_error(), nullptr)); \
        throw OpenSslException(__s + " at " __FILE__ ":" TOSTRING(__LINE__), __ret); \
    } while (0)


/**
 * Exception for errors from the libssl C library. Contains a message, as
 * well as a libssl return code.
 */
class OpenSslException : public std::system_error {
public:
    OpenSslException(const std::string& desc, int rc) :
        std::system_error(std::error_code(rc, std::generic_category()))
    {
        this->rc = rc;
        this->description = "OpenSSL exception: message=\"" + desc + "\", code=" + std::to_string(rc);
    }

    OpenSslException(const char* desc, int rc) :
        OpenSslException(desc == nullptr ? std::string() : std::string(desc), rc) {}

    const char* what() const throw() { return description.c_str(); }

    int get_rc() {
        auto code = std::system_error::code();
        return (int)code.value();
    }

private:
    int rc;
    std::string description;
};

namespace {
/// <summary>Truncates the given string-like container to the specified number of characters.</summary>
/// <param name="container">The container.</param>
/// <param name="numChars">The number of characters to truncate it to.</param>
template <class T>
std::string Truncate(const T& container, size_t numChars)
{
    return std::string(container.begin(), container.size() > numChars ? container.begin() + numChars : container.end());
}
}

namespace ApSecurity
{
namespace ExceptionUtil
{
/// <summary>Exception for errors received from APCA endpoints. Bubbles up contextual information to the caller.</summary>
class ApcaWebException : public std::system_error
{
public:
    /// <summary>Constructor.</summary>
    /// <param name="httpStatus">The HTTP status returned by APCA.</param>
    /// <param name="apcaAddresses">The APCA addresses that were attempted.</param>
    /// <param name="invokeHttpsResult">The result of the InvokeHttps call.</param>
    /// <param name="httpResponse">The HTTP response returned by APCA.</param>
    /// <param name="shortError">The short error message returned by APCA. Useful for, e.g., logging to MDM.</param>
    /// <param name="apcaUrlRelative">The relative APCA URL.</param>
    /// <remarks>
    /// 1. The HTTP response is truncated because it comes from a third party and can't be trusted.
    /// 2. The response is put into two places: the exception message which is passed into the base class constructor, and the m_serverError field.
    /// 3. We can't reuse m_serverError when calling the base class constructor, because it gets initialized after the base class constructor is called. An
    ///    alternative with many more lines of code is to put the exception message into another member variable and expose that by overriding what().
    /// </remarks>
    ApcaWebException(int httpStatus, const std::string& apcaAddresses, unsigned long invokeHttpsResult, const std::vector<BYTE>& httpResponse, const std::string& shortError, const std::string& apcaUrlRelative)
      : std::system_error(
            std::error_code(httpStatus, std::generic_category()),
            std::string("Invoking APCA with retry address '").append(apcaAddresses).append("', partial URL '").append(apcaUrlRelative).append("' failed with error ").append(std::to_string(invokeHttpsResult)).append(". HTTP ").append(std::to_string(httpStatus)).append(". Error response is: ").append(Truncate(httpResponse, 1024)).c_str()),
        m_serverError(Truncate(httpResponse, 1024)),
        m_serverErrorShort(Truncate(shortError, 128)),
        m_invokeHttpsResult(invokeHttpsResult),
        m_apcaEndpoint(apcaUrlRelative.substr(0, apcaUrlRelative.find('?'))) // Strip off the query parameters. TODO: This is a bit hacky, especially if we need to store the query params in a separate field in the future. Ideally, InvokeHttpsWithRetry should take the relative URL and query params as two separate arguments, and pass them to this constructor separately.
    {}

    /// <summary>The result of the InvokeHttps call.</summary>
    const unsigned long m_invokeHttpsResult;

    /// <summary>The error returned by APCA.</summary>
    const std::string m_serverError;

    /// <summary>The short error returned by APCA.</summary>
    const std::string m_serverErrorShort;

    /// <summary>The APCA endpoint.</summary>
    const std::string m_apcaEndpoint;
};
}
}
