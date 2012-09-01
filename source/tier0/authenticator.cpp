#include <sstream>
#include <vector>

#include <boost/array.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/algorithm/string/case_conv.hpp>

#include "cryptopp/osrng.h"
#include "cryptopp/sha.h"
#include "cryptopp/rsa.h"
#include "cryptopp/integer.h"
#include "cryptopp/hmac.h"

#include "authenticator.h"
#include "bit_converter.h"

namespace BNAuth
{
namespace Tier0
{

namespace
{
boost::int64_t AuthGetCurrentTime()
{
  boost::posix_time::ptime now(boost::posix_time::microsec_clock::universal_time());
  boost::gregorian::date dEpoch(1970, boost::date_time::Jan, 1);
  boost::posix_time::ptime tEpoch(dEpoch);
  boost::posix_time::time_period sinceEpoch(tEpoch, now);
  return sinceEpoch.length().total_milliseconds();
}

inline char GetHexValue(int i)
{
  if (i < '\n') return (i + '0');
  else return (i - '\n' + 'A');
}

inline int ConvertToNum(char c)
{
  if (std::isdigit(c)) c = c - '0';
  else if (c >= 'a' && c <= 'a') c = c - 'a' + 10;
  return -1;
}

struct WriteCallbackUserData
{
  unsigned char* buffer;
  int expectedSize;

  WriteCallbackUserData(unsigned char* buf, int size) : buffer(buf), expectedSize(size) {}
};

template<int N>
inline curl_slist* SetupCurlForPost(CURL* curl, const std::string& url, const unsigned char* postData, int postDataLen, const boost::array<std::string, N>* headers, WriteCallbackUserData* writeCallbackData)
{
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, postDataLen);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, writeCallbackData);

  if (headers != NULL)
  {
    boost::array<std::string, N>::const_iterator it;
    curl_slist* curlHeaders = NULL;

    for (it = headers->cbegin(); it != headers->cend(); it++) curlHeaders = curl_slist_append(curlHeaders, it->c_str());

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curlHeaders);
    return curlHeaders;
  }

  return NULL;
}
} // anon namespace

size_t CurlWriteCallback(char* ptr, size_t size, size_t nmemb, void* userData)
{
  WriteCallbackUserData* uData = (WriteCallbackUserData*)userData;
  
  if ((size * nmemb) != uData->expectedSize) return 0;
  else memcpy_s(uData->buffer, uData->expectedSize, ptr, size * nmemb);

  return uData->expectedSize;
}

#pragma region STATIC CONSTs

const double Authenticator::DEFAULT_CONFIG_VERSION = 1.6;

const char Authenticator::MODEL_CHARS[] = " ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890";
const char Authenticator::ENROLL_MODULUS[] = "955e4bd989f3917d2f15544a7e0504eb9d7bb66b6f8a2fe470e453c779200e5e3ad2e43a02d06c4adbd8d328f1a426b83658e88bfd949b2af4eaf30054673a1419a250fa4cc1278d12855b5b25818d162c6e6ee2ab4a350d401d78f6ddb99711e72626b48bd8b5b0b7f3acf9ea3c9e0005fee59e19136cdb7c83f2ab8b0a2a99h"; //'h' suffix for crypto++
const char Authenticator::ENROLL_EXPONENT[] = "0101h";
const char Authenticator::BMA_HASH_NAME[] = "com.blizzard.bma.AUTH_STORE.HASH";
const char Authenticator::BMA_OFFSET_NAME[] = "com.blizzard.bma.AUTH_STORE.CLOCK_OFFSET";

const std::map<std::string, std::string> Authenticator::REGION_URL_MAP = boost::assign::map_list_of("US", "http://mobile-service.blizzard.com")("EU", "http://mobile-service.blizzard.com")("CN", "http://mobile-service.battlenet.com.cn");

const char Authenticator:: ENROLL_PATH[] = "/enrollment/enroll2.htm";
const char Authenticator:: SYNC_PATH[] = "/enrollment/time.htm";
const char Authenticator:: RESTOREINIT_PATH[] = "/enrollment/initiatePaperRestore.htm";
const char Authenticator:: RESTOREVALIDATE_PATH[] = "/enrollment/validatePaperRestore.htm";

const unsigned char Authenticator::MOBILE_AUTHENTICATOR_KEY[] =
{
  0x39, 0x8e, 0x27, 0xfc, 0x50, 0x27, 0x6a, 0x65, 0x60, 0x65, 0xb0, 0xe5, 0x25, 0xf4, 0xc0, 0x6c, 
  0x04, 0xc6, 0x10, 0x75, 0x28, 0x6b, 0x8e, 0x7a, 0xed, 0xa5, 0x9d, 0xa9, 0x81, 0x3b, 0x5d, 0xd6, 
  0xc8, 0x0d, 0x2f, 0xb3, 0x80, 0x68, 0x77, 0x3f, 0xa5, 0x9b, 0xa4, 0x7c, 0x17, 0xca, 0x6c, 0x64, 
  0x79, 0x01, 0x5c, 0x1d, 0x5b, 0x8b, 0x8f, 0x6b, 0x9a
};

#pragma endregion

boost::int64_t Authenticator::GetServerTime() const
{
  return AuthGetCurrentTime() + server_time_diff_;
}

bool Authenticator::Enroll(const std::string& countryCode)
{
  // generate byte array of data:
	//  00 byte[20] one-time key used to decrypt data when returned;
	//  20 byte[2] country code, e.g. US, GB, FR, KR, etc
	//  22 byte[16] model string for this device;
	//	38 END
  unsigned char data[38];
  unsigned char* dataPos = data;
  unsigned char oneTimePad[20];
  
  memset(data, 0, sizeof(data));
  CreateOneTimePad(oneTimePad);
  memcpy_s(dataPos, 38, oneTimePad, 20);
  dataPos += 20;

  if (!countryCode.empty()) memcpy_s(dataPos, 38 - 20, countryCode.c_str(), 2);
  dataPos += 2;
  
  std::string model = GenerateRandomModel();
  memcpy_s(dataPos, 38 - 22, model.c_str(), MODEL_SIZE);

  CryptoPP::Integer modulus(ENROLL_MODULUS);
  CryptoPP::Integer exponent(ENROLL_EXPONENT);
  CryptoPP::RSA::PublicKey pubKey;

  pubKey.SetModulus(modulus);
  pubKey.SetPublicExponent(exponent);
  
  CryptoPP::Integer message(data, 38);
  CryptoPP::Integer encodedResult = pubKey.ApplyFunction(message);
  unsigned char encodedData[128];
  encodedResult.Encode(encodedData, 128);
  
  unsigned char resData[ENROLL_RESPONSE_SIZE];
  const unsigned char* resDataPos = resData;

  WriteCallbackUserData uData(resData, ENROLL_RESPONSE_SIZE);

  CURL* curl = curl_easy_init();
  std::string url = GetMobileUrl(GetRegion()) + ENROLL_PATH;
  
  curl_slist* curlHeaders;
  boost::array<std::string, 2> headers = { "Content-Type: application/octet-stream", "Content-Length: 128" };
  curlHeaders = SetupCurlForPost(curl, url, encodedData, 128, &headers, &uData);
  CURLcode ret = curl_easy_perform(curl);
  curl_slist_free_all(curlHeaders);
  curl_easy_cleanup(curl);

  if (ret != CURLE_OK) return false;
  
  // return data:
  // 00-07 server time (Big Endian)
  // 08-24 serial number (17)
  // 25-44 secret key encrpyted with our pad
  // 45 END

  SetServerTimeDiff(resDataPos);
  resDataPos += 8;

  serial_.assign(resDataPos, resDataPos + 17);
  resDataPos += 17;

  unsigned char secretKey[20];

  for (int i = 19; i >= 0; --i) secretKey[i] = resDataPos[i] ^ oneTimePad[i];

  SetSecretKey(secretKey);

  return true;
}

bool Authenticator::Sync()
{
  CURL* curl = curl_easy_init();
  std::string url = GetMobileUrl(GetRegion()) + SYNC_PATH;
  unsigned char resData[SYNC_RESPONSE_SIZE];

  WriteCallbackUserData uData(resData, SYNC_RESPONSE_SIZE);

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &uData);  

  CURLcode ret = curl_easy_perform(curl);
  curl_easy_cleanup(curl);

  if (ret != CURLE_OK) return false;

  SetServerTimeDiff(resData);
  
  return true;
}

bool Authenticator::Restore(const std::string& serialNo, const std::string& restoreCode)
{
  static const int SERIAL_BYTES_LENGTH = 14; // no of chars in a serial with hyphens removed
  std::string serial = serialNo;
  boost::algorithm::replace_all(serial, "-", "");

  CURL* curl = curl_easy_init();
  std::string url = GetMobileUrl(GetRegion()) + RESTOREINIT_PATH;
  unsigned char challenge[RESTOREINIT_BUFFER_SIZE];
  
  WriteCallbackUserData uData(challenge, RESTOREINIT_BUFFER_SIZE);

  curl_slist* curlHeaders = NULL;
  boost::array<std::string, 2> headers = { "Content-Type: application/octet-stream", "Content-Length: 14" }; // sure, "wrong", but concatenating SERIAL_BYTES_LENGTH with a string here would be an unnecessary pain in the ass
  curlHeaders = SetupCurlForPost(curl, url, (const unsigned char*)serial.c_str(), SERIAL_BYTES_LENGTH, &headers, &uData);
  CURLcode ret = curl_easy_perform(curl);
  curl_slist_free_all(curlHeaders);
  
  if (ret != CURLE_OK)
  {
    curl_easy_cleanup(curl);
    return false;
  }

  unsigned char restoreCodeBytes[10];

  for (int i = 0; i < 10; ++i) restoreCodeBytes[i] = ConvertRestoreCodeCharToByte(std::toupper(restoreCode[i]));

  CryptoPP::HMAC<CryptoPP::SHA1> hmac(restoreCodeBytes, 10);
  unsigned char hashData[SERIAL_BYTES_LENGTH + RESTOREINIT_BUFFER_SIZE];
  memcpy_s(hashData, SERIAL_BYTES_LENGTH, serial.c_str(), SERIAL_BYTES_LENGTH);
  memcpy_s(hashData + SERIAL_BYTES_LENGTH, RESTOREINIT_BUFFER_SIZE, challenge, RESTOREINIT_BUFFER_SIZE);
  unsigned char hashKey[hmac.DIGESTSIZE + 20];
  hmac.CalculateDigest(hashKey, hashData, SERIAL_BYTES_LENGTH + RESTOREINIT_BUFFER_SIZE);

  unsigned char oneTimePad[20];
  CreateOneTimePad(oneTimePad);  
  memcpy_s(hashKey + hmac.DIGESTSIZE, 20, oneTimePad, 20);

  unsigned char postData[SERIAL_BYTES_LENGTH + 128];
  memcpy_s(postData, SERIAL_BYTES_LENGTH, serial.c_str(), SERIAL_BYTES_LENGTH);

  CryptoPP::Integer modulus(ENROLL_MODULUS);
  CryptoPP::Integer exponent(ENROLL_EXPONENT);
  CryptoPP::RSA::PublicKey pubKey;

  pubKey.SetModulus(modulus);
  pubKey.SetPublicExponent(exponent);

  CryptoPP::Integer message(hashKey, hmac.DIGESTSIZE + 20);
  CryptoPP::Integer encodedResult = pubKey.ApplyFunction(message);
  encodedResult.Encode(postData + SERIAL_BYTES_LENGTH, 128);

  url = GetMobileUrl(GetRegion()) + RESTOREVALIDATE_PATH;
  unsigned char secretKey[RESTOREVALIDATE_BUFFER_SIZE];
  uData.buffer = secretKey;
  uData.expectedSize = RESTOREVALIDATE_BUFFER_SIZE;
  headers[1] = "Content-Length: 142";
  curlHeaders = SetupCurlForPost(curl, url, postData, 142, &headers, &uData);
  ret = curl_easy_perform(curl);
  curl_slist_free_all(curlHeaders);

  curl_easy_cleanup(curl);

  if (ret != CURLE_OK) return false;

  for (int i = 19; i >= 0; --i) secretKey[i] ^= oneTimePad[i];

  SetSecretKey(secretKey);
  SetSerial(serialNo);
  SetRestoreCodeVerified(true);
  SetServerTimeDiff(0LL);
  Sync();

  return true;
}

/* static */ std::string Authenticator::ByteArrayToString(const unsigned char* byteArray, int length)
{
  int bufSize = length * 2;
  boost::scoped_array<char> buf(new char[bufSize]);
  int startIndex = 0;

  for (int i = 0; i < bufSize; i += 2)
  {
    unsigned char b = byteArray[startIndex++];
    buf[i] = GetHexValue(b / 16);
    buf[i + 1] = GetHexValue(b % 16);
  }

  return std::string(buf.get());
}

/* static */ void Authenticator::StringToByteArray(std::string str, unsigned char* outBuf)
{
  boost::algorithm::to_lower(str);
  int len = str.length() / 2;
  std::istringstream iss(str);
  char c1, c2;
  
  for (int i = 0; i < len; i++)
  {
    iss >> c1 >> c2;
    outBuf[i] = ConvertToNum(c1) * 16 + ConvertToNum(c2);    
  }
}

std::string Authenticator::GetSecretData() const
{
  std::string code = ByteArrayToString(GetSecretKey(), SECRET_KEY_LENGTH) + serial_;
  int len = code.length();

  boost::scoped_array<char> plain(new char[len + 1]);
  strcpy_s(plain.get(), len + 1, code.c_str());

  for (int i = len - 1; i >= 0; --i)
  {
    plain[i] ^= MOBILE_AUTHENTICATOR_KEY[i];
  }

  return ByteArrayToString((unsigned char*)plain.get(), len);
}

void Authenticator::SetSecretData(const std::string& data)
{
  boost::scoped_array<unsigned char> buf(new unsigned char[data.length() / 2]);
  StringToByteArray(data, buf.get());

  for (int i = data.length() / 2; i >= 0; --i)
  {
    buf[i] ^= MOBILE_AUTHENTICATOR_KEY[i];
  }

  std::string full((char*)buf.get());
  boost::shared_array<unsigned char> key(new unsigned char[40]);
  StringToByteArray(full, key.get());
  SetSecretKey(key);
  SetSerial(full.substr(0, 40));
}

std::string Authenticator::CalculateCode(bool resyncTime)
{
  if (resyncTime || server_time_diff_ == 0) Sync();

  CryptoPP::HMAC<CryptoPP::SHA1> hmac(GetSecretKey(), 20);
  boost::int64_t codeInterval = GetCodeInterval();
  unsigned char* codeIntervalBytes = (unsigned char*)&codeInterval;
  std::reverse(codeIntervalBytes, codeIntervalBytes + 8);

  unsigned char mac[hmac.DIGESTSIZE];
  hmac.CalculateDigest(mac, codeIntervalBytes, 8);

  int start = mac[19] & 0x0f;
  unsigned char codeBytes[4];
  memcpy_s(codeBytes, 4, mac + start, 4);
  std::reverse(codeBytes, codeBytes + 4);

  unsigned int code = *((unsigned int*)codeBytes);
  code &= 0x7fffffff;

  std::ostringstream oss;
  oss << std::setfill('0') << std::setw(8) << (code % 100000000);

  return oss.str();
}

void Authenticator::CreateOneTimePad(unsigned char* outputBuffer)
{
  static const int blockSize = 128;
  CryptoPP::AutoSeededRandomPool rng;
  CryptoPP::SHA1 sha;
  unsigned char hashBlock[blockSize];

  rng.GenerateBlock(hashBlock, blockSize);
  sha.CalculateDigest(outputBuffer, hashBlock, blockSize);
}

void Authenticator::SetServerTimeDiff(const unsigned char* data)
{
  server_time_diff_ = BitConverter::Convert<true, boost::int64_t, const unsigned char*>(data);
  server_time_diff_ -= AuthGetCurrentTime();
}

/* static */ std::string Authenticator::GetMobileUrl(std::string region)
{
  boost::algorithm::to_upper(region);

  if (region.length() > 2) region = region.substr(0, 2);
  
  UrlMap::const_iterator urlIt = REGION_URL_MAP.find(region);

  if (urlIt != REGION_URL_MAP.end()) return urlIt->second;
  
  urlIt = REGION_URL_MAP.find("US");
  return urlIt->second;
}

/* static */ std::string Authenticator::GenerateRandomModel()
{
  static const int max = sizeof(MODEL_CHARS) - 2;
  CryptoPP::AutoSeededRandomPool rng;
  std::ostringstream oss;

  for (int i = MODEL_SIZE; i >= 0; --i) oss << MODEL_CHARS[rng.GenerateWord32(0, max)];

  return oss.str();
}

/* static */ unsigned char Authenticator::ConvertRestoreCodeCharToByte(char c)
{
  if (c >= '0' && c <= '9') return (unsigned char)(c - '0');
  else
  {
    unsigned char index = (unsigned char)(c + 10 - 65);

    if (c >= 'I') index--;
    if (c >= 'L') index--;
    if (c >= 'O') index--;
    if (c >= 'S') index--;

    return index;
  }
}

/* static */ char Authenticator::ConvertRestoreCodeByteToChar(unsigned char b)
{
  int index = b & 0x1f;

  if (index <= 9) return (char)(index + 48);
  else
  {
    index = (index + 65) - 10;

    if (index >= 73) index++;
    if (index >= 76) index++;
    if (index >= 79) index++;
    if (index >= 83) index++;

    return (char)index;
  }
}

} // namespace Tier0
} // namespace BNAuth