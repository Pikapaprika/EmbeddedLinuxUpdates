#ifndef UPDATECLIENT_UPDATEDOWNLOADCLIENT_H
#define UPDATECLIENT_UPDATEDOWNLOADCLIENT_H

#include <iostream>
#include <sstream>
#include <vector>
#include <chrono>
#include <thread>
#include <array>
#include <map>
#include <curl/curl.h>
#include "nlohmann/json.hpp"
#include "ArtifactCryptoHelper.h"
#include "ArtifactParser.h"
#include <exception>

class fetch_exception : public std::runtime_error {
public:
    explicit fetch_exception(const char *message) : std::runtime_error(message) {}
};


// Getter-Setter, base class?
struct DecryptionKeyServerResponse {
    std::array<unsigned char, 256> key;
    std::array<unsigned char, 12> iv;
    long httpCode;
};

struct UpdateArtifactServerResponse {
    std::vector <unsigned char> artifact;
    long httpCode;
};

class UpdateDownloadClient {
private:

    std::string serverAddr;
    std::chrono::milliseconds pollInterval;
    std::string caCertPath;
    std::string certPath;
    std::string keyPath;
    int retries;

    // Used by libCURL to write the content of HTTP-Responses into the configured buffer
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        ((std::string*) userp)->append((char*) contents, size * nmemb);
        return size * nmemb;
    }

    static std::string BuildParameterString(const std::map<std::string, std::string>& params);

    static long GetHttpResponseCode(CURL* curl);

    bool DoStandardCurlSetup(CURL* curl, const std::string& endpoint,
                             const std::string& writeBuffer, const std::string& errorBuffer,
                             const std::map<std::string, std::string>* params = nullptr);

public:

    static void GlobalInit();

    static void GlobalCleanup();

    UpdateArtifactServerResponse FetchArtifact(uint updateId);

    DecryptionKeyServerResponse FetchDecryptionKey(uint updateId);

    std::vector<unsigned int> StartPolling();

    explicit UpdateDownloadClient(std::string serverAddr, std::chrono::milliseconds pollInterval,
                                  std::string caCertPath, std::string certPath,
                                  std::string keyPath, int retries) noexcept;
    std::string DoConnectionTest();
};

#endif //UPDATECLIENT_UPDATEDOWNLOADCLIENT_H
