#ifndef BNAUTH__BNAUTH_H__
#define BNAUTH__BNAUTH_H__

#ifdef WIN32
# ifndef BNAUTH_API
#  if defined(TIER0_EXPORTS) || defined(TIER1_EXPORTS)
#   define BNAUTH_API __declspec(dllexport)
#   define TEMPLATE_EXPIMP
#  else
#   define BNAUTH_API __declspec(dllimport)
#   define TEMPLATE_EXPIMP extern
#  endif
# endif
#else
# ifndef BNAUTH_API
#  define BNAUTH_API
#  define TEMPLATE_EXPIMP
# endif
#endif

#endif