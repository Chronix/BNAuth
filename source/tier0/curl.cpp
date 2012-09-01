class CurlInitializer
{
public:
  CurlInitializer() { curl_global_init(CURL_GLOBAL_ALL); }
  ~CurlInitializer() { curl_global_cleanup(); }
};

static CurlInitializer g_curlInit;