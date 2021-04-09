#include "UpdateDownloadClient.h"

const std::string ENDPOINT_WHATS_NEW = "/whatsNew";
const std::string ENDPOINT_GET_UPDATE = "/getUpdate";
const std::string ENDPOINT_GET_DECRYPTION_KEY = "/getDecryptionKey";

// Called by nlohmann-JSON-library when parsing JSON
void from_json(const nlohmann::json& j, DecryptionKeyServerResponse& pair) {
    j.at("ct").get_to(pair.key);
    j.at("iv").get_to(pair.iv);
}

std::string UpdateDownloadClient::BuildParameterString(const std::map<std::string, std::string>& params) {
    std::ostringstream urlStrm;
    for (auto const&[key, val] : params) {
        if (urlStrm.str().empty()) {
            urlStrm << "?" << key << "=" << val;
        } else {
            urlStrm << "&" << key << "=" << val;
        }
    }
    return urlStrm.str();
}

bool UpdateDownloadClient::DoStandardCurlSetup(CURL* curl, const std::string& endpoint,
                                               const std::string& writeBuffer, const std::string& errorBuffer,
                                               const std::map<std::string, std::string>* params) {

    std::string uri = serverAddr;
    if (endpoint == ENDPOINT_WHATS_NEW) {
        uri += ENDPOINT_WHATS_NEW;
    } else if (endpoint == ENDPOINT_GET_UPDATE) {
        uri += ENDPOINT_GET_UPDATE;
    } else if (endpoint == ENDPOINT_GET_DECRYPTION_KEY) {
        uri += ENDPOINT_GET_DECRYPTION_KEY;
    } else {
        return false;
    }

    if (params != nullptr) {
        auto paramString = BuildParameterString(*params);
        uri += paramString;
    }

    curl_easy_setopt(curl, CURLOPT_URL, uri.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, caCertPath.c_str());

    curl_easy_setopt(curl, CURLOPT_CAINFO, caCertPath.c_str());

    curl_easy_setopt(curl, CURLOPT_SSLKEY, keyPath.c_str());
    curl_easy_setopt(curl, CURLOPT_SSLCERT, certPath.c_str());

    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &writeBuffer);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer.data());

    return true;
}

long UpdateDownloadClient::GetHttpResponseCode(CURL* curl) {
    long httpCode = 0;
    auto curlCode = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    if (curlCode != 0) {
        return -1;
    }
    return httpCode;
}

UpdateDownloadClient::UpdateDownloadClient(std::string serverAddr, std::chrono::milliseconds pollInterval,
                                           std::string caCertPath, std::string certPath,
                                           std::string keyPat, int retries) noexcept: serverAddr(std::move(serverAddr)),
                                                                          pollInterval(pollInterval),
                                                                          caCertPath(std::move(caCertPath)),
                                                                          certPath(std::move(certPath)),
                                                                          keyPath(std::move(keyPath)),
                                                                          retries{retries} {}

UpdateArtifactServerResponse UpdateDownloadClient::FetchArtifact(uint updateId) {
    auto curl = curl_easy_init();

    std::string writeBuffer;
    std::string errorBuffer;
    errorBuffer.resize(CURL_ERROR_SIZE);

    std::map<std::string, std::string> params;
    params["updateId"] = std::to_string(updateId);

    DoStandardCurlSetup(curl, ENDPOINT_GET_UPDATE, writeBuffer, errorBuffer, &params);

    auto code = curl_easy_perform(curl);

    if (code != 0) {
        throw fetch_exception(errorBuffer.c_str());
    }
    auto httpCode = GetHttpResponseCode(curl);

    UpdateArtifactServerResponse resp{};

    if (httpCode == 200) {
        std::vector<unsigned char> artifact(writeBuffer.begin(), writeBuffer.end());
        resp.artifact = std::move(artifact);
    }
    resp.httpCode = httpCode;

    return resp;
};

DecryptionKeyServerResponse UpdateDownloadClient::FetchDecryptionKey(uint updateId) {
    auto curl = curl_easy_init();

    std::string writeBuffer;
    std::string errorBuffer;
    errorBuffer.resize(CURL_ERROR_SIZE);

    std::map<std::string, std::string> params;
    params["updateId"] = std::to_string(updateId);

    DoStandardCurlSetup(curl, ENDPOINT_GET_DECRYPTION_KEY, writeBuffer, errorBuffer, &params);

    auto code = curl_easy_perform(curl);

    if (code != 0) {
        throw fetch_exception(errorBuffer.c_str());
    }

    auto httpCode = GetHttpResponseCode(curl);
    DecryptionKeyServerResponse response{};

    if (httpCode == 200) {
        auto j = nlohmann::json::parse(writeBuffer);
        response = j.get<DecryptionKeyServerResponse>();
    }
    response.httpCode = httpCode;

    return response;
}

std::vector<unsigned int> UpdateDownloadClient::StartPolling() {

    auto curl = curl_easy_init();

    std::string writeBuffer;
    std::string errorBuffer;
    errorBuffer.resize(CURL_ERROR_SIZE);

    DoStandardCurlSetup(curl, ENDPOINT_WHATS_NEW, writeBuffer, errorBuffer);

    std::vector<unsigned int> updates;

    while (true) {

        writeBuffer.clear();
        auto code = curl_easy_perform(curl);

        if (code != 0) {
            std::cout << std::string(errorBuffer) << "\n";
            std::this_thread::sleep_for(pollInterval);
            continue;
        }

        auto httpCode = GetHttpResponseCode(curl);

        if (httpCode == 200) {
            nlohmann::json j = nlohmann::json::parse(writeBuffer);
            updates = j.get<std::vector<unsigned int>>();
            break;
        }

        std::this_thread::sleep_for(pollInterval);
    }

    curl_easy_cleanup(curl);
    return updates;
}

std::string UpdateDownloadClient::DoConnectionTest() {

    auto curl = curl_easy_init();

    std::string writeBuffer;
    std::string errorBuffer;
    errorBuffer.resize(CURL_ERROR_SIZE);

    DoStandardCurlSetup(curl, ENDPOINT_WHATS_NEW, writeBuffer, errorBuffer);

    for (int i = 0; i < retries; i++) {

        writeBuffer.clear();
        auto code = curl_easy_perform(curl);

        if (code == 0) {
            return "";
        }

        std::cout << std::string(errorBuffer) << "\n";
        // for now, use same interval as is used for polling
        std::this_thread::sleep_for(pollInterval);
    }
    return std::string(errorBuffer);
}

bool globalInitCalled = false;

void UpdateDownloadClient::GlobalInit() {
    if (globalInitCalled) {
        return;
    }
    curl_global_init(CURL_GLOBAL_DEFAULT);
    globalInitCalled = true;
}

void UpdateDownloadClient::GlobalCleanup() {
    if (globalInitCalled) {
        curl_global_cleanup();
        globalInitCalled = false;
    }
}

