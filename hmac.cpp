#include <curl/curl.h>
#include <string>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <openssl/hmac.h>
#include "SunnyCABundle.h"

static std::string ToHex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return oss.str();
}

static std::string HmacSha256Hex(const std::string& secret, const std::string& message) {
    unsigned int len = EVP_MAX_MD_SIZE;
    unsigned char out[EVP_MAX_MD_SIZE] = {0};
    HMAC(EVP_sha256(),
         secret.data(), (int)secret.size(),
         reinterpret_cast<const unsigned char*>(message.data()), message.size(),
         out, &len);
    return ToHex(out, len);
}

// libcurl >= 7.77: use CA bundle from memory directly
static void ApplySunnyCABundle(CURL* curl) {
#ifdef CURLOPT_CAINFO_BLOB
    curl_blob blob;
    blob.data = (void*)SUNNY_CA_BUNDLE_PEM;
    blob.len = strlen(SUNNY_CA_BUNDLE_PEM);
    blob.flags = CURL_BLOB_COPY;
    curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &blob);
#endif
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
}

static size_t WriteCallback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* out = reinterpret_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

bool VerifyNovaKey(const std::string& apiKey, const std::string& deviceId, std::string& responseBody) {
    const std::string username = "novaapp";
    const std::string userHmacSecret = "REPLACE_WITH_YOUR_SECRET";
    const long ts = (long)std::time(nullptr);

    const std::string signPayload = username + "|" + apiKey + "|" + deviceId + "|" + std::to_string(ts);
    const std::string sigUser = HmacSha256Hex(userHmacSecret, signPayload);

    const std::string json =
        std::string("{") +
        "\"username\":\"" + username + "\"," +
        "\"key\":\"" + apiKey + "\"," +
        "\"device_id\":\"" + deviceId + "\"," +
        "\"ts\":" + std::to_string(ts) + "," +
        "\"sig_user\":\"" + sigUser + "\"" +
        "}";

    CURL* curl = curl_easy_init();
    if (!curl) return false;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, "https://ijvhlhdrncxtxosmnbtt.supabase.co/functions/v1/rent-verify-key");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)json.size());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    ApplySunnyCABundle(curl);

    const CURLcode res = curl_easy_perform(curl);
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK && httpCode >= 200 && httpCode < 300);
}
