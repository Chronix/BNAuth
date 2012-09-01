#ifndef BNAUTH__DLLHACKS_H__
#define BNAUTH__DLLHACKS_H__

#include <string>

#include <boost/shared_array.hpp>

#include "BNAuth.h"

#pragma warning(push)
#pragma warning(disable: 4231) // nonstandard extension used: extern before template explicit instantiation
TEMPLATE_EXPIMP template class BNAUTH_API std::allocator<char>;
TEMPLATE_EXPIMP template class BNAUTH_API std::basic_string<char, std::char_traits<char>, std::allocator<char>>;
#pragma warning(pop)

#endif