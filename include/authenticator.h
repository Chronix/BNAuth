#ifndef BNAUTH__TIER0_AUTHENTICATOR_H__
#define BNAUTH__TIER0_AUTHENTICATOR_H__

#include <string>
#include <map>

#include <boost/smart_ptr/scoped_array.hpp>
#include <boost/shared_array.hpp>
#include <boost/cstdint.hpp>

#include "BNAuth.h"
#include "DllHacks.h"

#define SECRET_KEY_LENGTH 20
#define HTTP_STATUS_OK 200

namespace BNAuth
{
namespace Tier0
{

enum BNAUTH_API AUTH_FILE_FORMAT
{
  AUTH_FILE_FORMAT_WINAUTH,
  AUTH_FILE_FORMAT_BMA,
  AUTH_FILE_FORMAT_MIDP
};

class BNAUTH_API Authenticator
{
public:
  Authenticator() : loaded_format_(AUTH_FILE_FORMAT_WINAUTH) { secret_key_.reset(new unsigned char[20]); }
  ~Authenticator() { }

  const unsigned char* GetSecretKey() const { return secret_key_.get(); }
  void SetSecretKey(const unsigned char* key) { memcpy_s(secret_key_.get(), 20, key, 20); }
  void SetSecretKey(const boost::shared_array<unsigned char>& arr) { secret_key_ = arr; }

  std::string GetSerial() const { return serial_; }
  void SetSerial(const std::string& serial) { serial_ = serial; }

  std::string GetRegion() const { return serial_.substr(0, 2); }

  bool GetRestoreCodeVerified() const { return restore_code_verified_; }
  void SetRestoreCodeVerified(bool b) { restore_code_verified_ = b; }

  boost::int64_t GetServerTimeDiff() const { return server_time_diff_; }
  void SetServerTimeDiff(boost::int64_t diff) { server_time_diff_ = diff; }

  std::string GetPassword() const { return password_; }
  void SetPassword(const std::string& pass) { password_ = pass; }

  AUTH_FILE_FORMAT GetLoadedFormat() const { return loaded_format_; }
  void SetLoadedFormat(AUTH_FILE_FORMAT fmt) { loaded_format_ = fmt; }

  boost::int64_t GetServerTime() const;
  boost::int64_t GetCodeInterval() const { return GetServerTime() / 30000LL; }
  std::string GetCurrentCode() { return CalculateCode(false); }

  bool Enroll(const std::string& countryCode);
  bool Sync();
  bool Restore(const std::string& serialNo, const std::string& restoreCode);

  static std::string ByteArrayToString(const unsigned char* byteArray, int length);
  static void StringToByteArray(std::string str, unsigned char* outBuf);

private:
  std::string GetSecretData() const;
  void SetSecretData(const std::string& data);

  std::string CalculateCode(bool resyncTime);
  void CreateOneTimePad(unsigned char* outputBuffer);
  void SetServerTimeDiff(const unsigned char* data);

  static std::string GetMobileUrl(std::string region);
  static std::string GenerateRandomModel();
  static unsigned char ConvertRestoreCodeCharToByte(char c);
  static char ConvertRestoreCodeByteToChar(unsigned char b);

  std::string serial_;
  bool restore_code_verified_;
  boost::int64_t server_time_diff_;
  std::string password_;
  AUTH_FILE_FORMAT loaded_format_;

#pragma warning(push)
#pragma warning(disable: 4251) // header-only class
  boost::shared_array<unsigned char> secret_key_;
#pragma warning(pop)

  static const int  MODEL_SIZE = 16;
  static const int  ENROLL_RESPONSE_SIZE = 45;
  static const int  SYNC_RESPONSE_SIZE = 8;
  static const int  RESTOREINIT_BUFFER_SIZE = 32;
  static const int  RESTOREVALIDATE_BUFFER_SIZE = 20;
  static const int  SALT_LENGTH = 8;
  static const int  PBKDF2_ITERATIONS = 2000;
  static const int  PBKDF2_KEYSIZE = 256;

  static const double DEFAULT_CONFIG_VERSION;

  static const char MODEL_CHARS[];
  static const char ENROLL_MODULUS[];
  static const char ENROLL_EXPONENT[];
  static const char BMA_HASH_NAME[];
  static const char BMA_OFFSET_NAME[];

#pragma warning(push)
#pragma warning(disable: 4251) // private var
  typedef std::map<std::string, std::string> UrlMap;
  static const UrlMap REGION_URL_MAP;
#pragma warning(pop)

  static const char ENROLL_PATH[];
  static const char SYNC_PATH[];
  static const char RESTOREINIT_PATH[];
  static const char RESTOREVALIDATE_PATH[];

  static const unsigned char MOBILE_AUTHENTICATOR_KEY[];

  friend size_t CurlWriteCallback(char* ptr, size_t size, size_t nmemb, void* userData);
};

}
}

#endif