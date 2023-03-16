#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>
#include "Utils.h"

std::vector<unsigned char> base64_to_binary(const std::string& base64_data)
{
    using namespace boost::archive::iterators;
    using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;

    // Remove any padding added during encoding
    std::string temp(base64_data.c_str(), base64_data.length());
    temp.erase(std::remove(temp.begin(), temp.end(), '='), temp.end());

    return std::vector<unsigned char>(It(std::begin(temp)), It(std::end(temp)));
}
