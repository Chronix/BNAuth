#include "authenticator.h"
#include <algorithm>

int main(int argc, char** argv)
{
  BNAuth::Tier0::Authenticator auth;
  bool res = auth.Restore("EU-1203-1662-3305", "VAF1H865KK");
  std::string testCode = auth.GetCurrentCode();
  return 0;
}