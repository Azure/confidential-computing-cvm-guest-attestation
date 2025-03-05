#include <string>
#include <stdexcept>
#include <sstream>
#include <openssl/err.h>

class OsslError : public std::runtime_error {
private:
    unsigned long errCode;
public:
    OsslError(unsigned long errCode, const std::string& description)
        : std::runtime_error(description), errCode(errCode) {}

    unsigned long getErrorCode() const { return errCode; }
    std::string getErrorInfo() const {
        char errInfo[256];
        ERR_error_string_n(errCode, errInfo, sizeof(errInfo));
        return std::string(errInfo);
    }
};