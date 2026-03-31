#include <array>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include "httplib.h"
#include "json.hpp"

using json = nlohmann::json;
using u8 = uint8_t;
using u64 = uint64_t;

static std::string safe_json_dump(const json& value) {
    return value.dump(-1, ' ', false, json::error_handler_t::replace);
}

// ============================================================
// UTF-8 helpers
// ============================================================
inline size_t utf8_char_length(unsigned char c) {
    if ((c & 0x80) == 0) return 1;
    if ((c & 0xE0) == 0xC0) return 2;
    if ((c & 0xF0) == 0xE0) return 3;
    if ((c & 0xF8) == 0xF0) return 4;
    return 1;
}

size_t utf8_length(const std::string& str) {
    size_t len = 0;
    size_t i = 0;
    while (i < str.length()) {
        i += utf8_char_length(static_cast<unsigned char>(str[i]));
        len++;
    }
    return len;
}

std::string utf8_substr(const std::string& str, size_t char_start, size_t char_len) {
    size_t byte_pos = 0;
    size_t chars_seen = 0;

    while (byte_pos < str.length() && chars_seen < char_start) {
        byte_pos += utf8_char_length(static_cast<unsigned char>(str[byte_pos]));
        chars_seen++;
    }

    size_t start_byte = byte_pos;
    chars_seen = 0;

    while (byte_pos < str.length() && chars_seen < char_len) {
        byte_pos += utf8_char_length(static_cast<unsigned char>(str[byte_pos]));
        chars_seen++;
    }

    return str.substr(start_byte, byte_pos - start_byte);
}

// ============================================================
// Masking rules
// ============================================================
std::string maskName(const std::string& name) {
    if (name.empty()) return name;
    const size_t len = utf8_length(name);
    if (len <= 4) return utf8_substr(name, 0, 1) + "***";
    return utf8_substr(name, 0, 2) + "***" + utf8_substr(name, len - 2, 2);
}

std::string maskPhone(const std::string& phone) {
    std::string digits;
    for (char c : phone) {
        if (std::isdigit(static_cast<unsigned char>(c)) || c == '+') digits += c;
    }
    if (digits.length() <= 6) return "***";
    return digits.substr(0, 3) + "****" + digits.substr(digits.length() - 3);
}

std::string maskEmail(const std::string& email) {
    const size_t atPos = email.find('@');
    if (atPos == std::string::npos) return "***";

    const std::string local = email.substr(0, atPos);
    const std::string domain = email.substr(atPos);
    const size_t localLen = utf8_length(local);

    if (localLen <= 3) return utf8_substr(local, 0, 1) + "****" + domain;
    return utf8_substr(local, 0, 3) + "****" + domain;
}

std::string maskAddress(const std::string& address) {
    if (address.empty()) return address;
    const size_t len = utf8_length(address);

    if (len <= 10) return utf8_substr(address, 0, 3) + "****";
    if (5 + 8 >= len) return utf8_substr(address, 0, 3) + "****";
    return utf8_substr(address, 0, 5) + "****" + utf8_substr(address, len - 8, 8);
}

std::string maskNote(const std::string& note) {
    if (note.empty()) return note;
    const size_t len = utf8_length(note);
    if (len <= 8) return utf8_substr(note, 0, 2) + "***";
    return utf8_substr(note, 0, 4) + "***" + utf8_substr(note, len - 4, 4);
}

void applyMasking(json& body) {
    if (body.contains("receiver_name") && body["receiver_name"].is_string()) {
        body["receiver_name"] = maskName(body["receiver_name"].get<std::string>());
    }
    if (body.contains("receiver_phone") && body["receiver_phone"].is_string()) {
        body["receiver_phone"] = maskPhone(body["receiver_phone"].get<std::string>());
    }
    if (body.contains("receiver_email") && body["receiver_email"].is_string()) {
        body["receiver_email"] = maskEmail(body["receiver_email"].get<std::string>());
    }
    if (body.contains("shipping_address") && body["shipping_address"].is_string()) {
        body["shipping_address"] = maskAddress(body["shipping_address"].get<std::string>());
    }
    if (body.contains("notes") && body["notes"].is_string()) {
        body["notes"] = maskNote(body["notes"].get<std::string>());
    }
}

// ============================================================
// Random bytes + Base64
// ============================================================
std::vector<u8> randomBytes(size_t n) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    std::vector<u8> out(n);
    for (size_t i = 0; i < n; i++) out[i] = static_cast<u8>(dist(gen));
    return out;
}

std::string base64Encode(const std::vector<u8>& data) {
    static const char* TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i + 2 < data.size()) {
        const uint32_t triple = (static_cast<uint32_t>(data[i]) << 16) |
                                (static_cast<uint32_t>(data[i + 1]) << 8) |
                                static_cast<uint32_t>(data[i + 2]);
        out.push_back(TABLE[(triple >> 18) & 0x3F]);
        out.push_back(TABLE[(triple >> 12) & 0x3F]);
        out.push_back(TABLE[(triple >> 6) & 0x3F]);
        out.push_back(TABLE[triple & 0x3F]);
        i += 3;
    }

    if (i < data.size()) {
        const uint32_t a = data[i];
        const uint32_t b = (i + 1 < data.size()) ? data[i + 1] : 0;
        const uint32_t triple = (a << 16) | (b << 8);
        out.push_back(TABLE[(triple >> 18) & 0x3F]);
        out.push_back(TABLE[(triple >> 12) & 0x3F]);
        if (i + 1 < data.size()) {
            out.push_back(TABLE[(triple >> 6) & 0x3F]);
            out.push_back('=');
        } else {
            out.push_back('=');
            out.push_back('=');
        }
    }

    return out;
}

std::vector<u8> base64Decode(const std::string& input) {
    static std::array<int, 256> T = [] {
        std::array<int, 256> table{};
        table.fill(-1);
        const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < static_cast<int>(alphabet.size()); i++) {
            table[static_cast<unsigned char>(alphabet[i])] = i;
        }
        return table;
    }();

    std::vector<u8> out;
    int val = 0;
    int valb = -8;
    for (unsigned char c : input) {
        if (std::isspace(c)) continue;
        if (c == '=') break;
        int d = T[c];
        if (d == -1) break;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<u8>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// ============================================================
// AES-128 (logic implementation, CTR mode)
// ============================================================
static constexpr std::array<u8, 256> SBOX = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static constexpr std::array<u8, 11> RCON = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};

u8 xtime(u8 x) {
    return static_cast<u8>((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

void subBytes(std::array<u8, 16>& state) {
    for (auto& b : state) b = SBOX[b];
}

void shiftRows(std::array<u8, 16>& state) {
    std::array<u8, 16> tmp = state;
    state[0] = tmp[0];   state[4] = tmp[4];   state[8] = tmp[8];   state[12] = tmp[12];
    state[1] = tmp[5];   state[5] = tmp[9];   state[9] = tmp[13];  state[13] = tmp[1];
    state[2] = tmp[10];  state[6] = tmp[14];  state[10] = tmp[2];  state[14] = tmp[6];
    state[3] = tmp[15];  state[7] = tmp[3];   state[11] = tmp[7];  state[15] = tmp[11];
}

void mixColumns(std::array<u8, 16>& state) {
    for (int i = 0; i < 4; i++) {
        const int c = i * 4;
        const u8 a0 = state[c + 0];
        const u8 a1 = state[c + 1];
        const u8 a2 = state[c + 2];
        const u8 a3 = state[c + 3];
        const u8 t = static_cast<u8>(a0 ^ a1 ^ a2 ^ a3);
        const u8 u = a0;
        state[c + 0] ^= static_cast<u8>(t ^ xtime(a0 ^ a1));
        state[c + 1] ^= static_cast<u8>(t ^ xtime(a1 ^ a2));
        state[c + 2] ^= static_cast<u8>(t ^ xtime(a2 ^ a3));
        state[c + 3] ^= static_cast<u8>(t ^ xtime(a3 ^ u));
    }
}

void addRoundKey(std::array<u8, 16>& state, const std::array<u8, 176>& roundKey, int round) {
    const int base = round * 16;
    for (int i = 0; i < 16; i++) state[i] ^= roundKey[base + i];
}

std::array<u8, 176> keyExpansion(const std::array<u8, 16>& key) {
    std::array<u8, 176> roundKey{};
    for (int i = 0; i < 16; i++) roundKey[i] = key[i];

    int bytesGenerated = 16;
    int rconIteration = 1;
    std::array<u8, 4> temp{};

    while (bytesGenerated < 176) {
        for (int i = 0; i < 4; i++) {
            temp[i] = roundKey[bytesGenerated - 4 + i];
        }

        if (bytesGenerated % 16 == 0) {
            const u8 k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;

            for (int i = 0; i < 4; i++) temp[i] = SBOX[temp[i]];
            temp[0] ^= RCON[rconIteration++];
        }

        for (int i = 0; i < 4; i++) {
            roundKey[bytesGenerated] = static_cast<u8>(roundKey[bytesGenerated - 16] ^ temp[i]);
            bytesGenerated++;
        }
    }

    return roundKey;
}

std::array<u8, 16> aes128EncryptBlock(const std::array<u8, 16>& input, const std::array<u8, 16>& key) {
    auto state = input;
    const auto roundKey = keyExpansion(key);

    addRoundKey(state, roundKey, 0);

    for (int round = 1; round <= 9; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKey, round);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKey, 10);
    return state;
}

void incrementCounter(std::array<u8, 16>& counter) {
    for (int i = 15; i >= 0; --i) {
        counter[i] = static_cast<u8>(counter[i] + 1);
        if (counter[i] != 0) break;
    }
}

std::vector<u8> aes128CtrTransform(
    const std::vector<u8>& input,
    const std::array<u8, 16>& key,
    const std::array<u8, 16>& iv
) {
    std::vector<u8> out(input.size());
    std::array<u8, 16> counter = iv;
    size_t offset = 0;

    while (offset < input.size()) {
        const auto keystream = aes128EncryptBlock(counter, key);
        const size_t blockSize = std::min<size_t>(16, input.size() - offset);
        for (size_t i = 0; i < blockSize; i++) {
            out[offset + i] = static_cast<u8>(input[offset + i] ^ keystream[i]);
        }
        offset += blockSize;
        incrementCounter(counter);
    }

    return out;
}

// ============================================================
// RSA (logic implementation over uint64, demo-safe only)
// ============================================================
u64 modMul(u64 a, u64 b, u64 mod) {
    u64 result = 0;
    u64 x = a % mod;
    u64 y = b;
    while (y > 0) {
        if (y & 1ULL) {
            result = (result + x) % mod;
        }
        x = (x * 2ULL) % mod;
        y >>= 1ULL;
    }
    return result;
}

u64 modPow(u64 base, u64 exp, u64 mod) {
    u64 result = 1 % mod;
    u64 cur = base % mod;
    u64 e = exp;
    while (e > 0) {
        if (e & 1ULL) result = modMul(result, cur, mod);
        cur = modMul(cur, cur, mod);
        e >>= 1ULL;
    }
    return result;
}

std::vector<std::string> rsaEncryptBytes(const std::vector<u8>& input, u64 e, u64 n) {
    std::vector<std::string> out;
    out.reserve(input.size());
    for (u8 b : input) {
        const u64 c = modPow(static_cast<u64>(b), e, n);
        out.push_back(std::to_string(c));
    }
    return out;
}

bool parseU64(const std::string& text, u64& out) {
    try {
        size_t idx = 0;
        const unsigned long long value = std::stoull(text, &idx, 10);
        if (idx != text.size()) return false;
        out = static_cast<u64>(value);
        return true;
    } catch (...) {
        return false;
    }
}

// ============================================================
// HTTP server
// ============================================================
int main() {
    httplib::Server svr;

    svr.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) -> httplib::Server::HandlerResponse {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, X-Client-Rsa-N, X-Client-Rsa-E");
        if (req.method == "OPTIONS") {
            res.status = 204;
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });

    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        json response = {
            {"status", "ok"},
            {"service", "data-masking"},
            {"version", "2.0.0"}
        };
        res.set_content(safe_json_dump(response), "application/json");
    });

    // Legacy: only masking
    svr.Post("/mask", [](const httplib::Request& req, httplib::Response& res) {
        try {
            json body = json::parse(req.body);
            applyMasking(body);
            res.set_content(safe_json_dump(body), "application/json");
        } catch (const std::exception& e) {
            json error = {
                {"error", "Invalid request"},
                {"detail", e.what()}
            };
            res.status = 400;
            res.set_content(safe_json_dump(error), "application/json");
        }
    });

    // New flow: masking + AES + RSA in service
    svr.Post("/secure-mask", [](const httplib::Request& req, httplib::Response& res) {
        try {
            json body = json::parse(req.body);
            if (!body.contains("data") || !body["data"].is_object()) {
                res.status = 400;
                res.set_content(R"({"error":"Missing data object"})", "application/json");
                return;
            }
            if (!body.contains("rsa") || !body["rsa"].is_object()) {
                res.status = 400;
                res.set_content(R"({"error":"Missing rsa object"})", "application/json");
                return;
            }

            json masked = body["data"];
            applyMasking(masked);

            const json rsaObj = body["rsa"];
            if (!rsaObj.contains("n") || !rsaObj.contains("e")) {
                res.status = 400;
                res.set_content(R"({"error":"Missing rsa.n or rsa.e"})", "application/json");
                return;
            }

            u64 n = 0;
            u64 e = 0;
            const std::string nStr = rsaObj["n"].is_string() ? rsaObj["n"].get<std::string>() : std::to_string(rsaObj["n"].get<u64>());
            const std::string eStr = rsaObj["e"].is_string() ? rsaObj["e"].get<std::string>() : std::to_string(rsaObj["e"].get<u64>());
            if (!parseU64(nStr, n) || !parseU64(eStr, e) || n <= 257 || e <= 1) {
                res.status = 400;
                res.set_content(R"({"error":"Invalid RSA n/e"})", "application/json");
                return;
            }

            const std::string plaintext = safe_json_dump(masked);
            std::vector<u8> plaintextBytes(plaintext.begin(), plaintext.end());

            const auto keyBytes = randomBytes(16);
            const auto ivBytes = randomBytes(16);
            std::array<u8, 16> key{};
            std::array<u8, 16> iv{};
            std::copy(keyBytes.begin(), keyBytes.end(), key.begin());
            std::copy(ivBytes.begin(), ivBytes.end(), iv.begin());

            const auto cipherBytes = aes128CtrTransform(plaintextBytes, key, iv);
            const auto encryptedKey = rsaEncryptBytes(keyBytes, e, n);

            json response = {
                {"encrypted", true},
                {"cipher", "AES-128-CTR"},
                {"key_alg", "RSA"},
                {"payload", base64Encode(cipherBytes)},
                {"iv", base64Encode(ivBytes)},
                {"encrypted_key", encryptedKey}
            };
            res.set_content(safe_json_dump(response), "application/json");
        } catch (const std::exception& e) {
            json error = {
                {"error", "Internal error"},
                {"detail", e.what()}
            };
            res.status = 500;
            res.set_content(safe_json_dump(error), "application/json");
        }
    });

    // Decrypt flow: decrypt AES key by RSA private key, then decrypt payload.
    svr.Post("/decrypt", [](const httplib::Request& req, httplib::Response& res) {
        try {
            json body = json::parse(req.body);
            if (!body.contains("encrypted_data") || !body["encrypted_data"].is_object()) {
                res.status = 400;
                res.set_content(R"({"error":"Missing encrypted_data object"})", "application/json");
                return;
            }
            if (!body.contains("rsa") || !body["rsa"].is_object()) {
                res.status = 400;
                res.set_content(R"({"error":"Missing rsa object"})", "application/json");
                return;
            }

            const json encryptedData = body["encrypted_data"];
            const json rsaObj = body["rsa"];

            if (!encryptedData.contains("payload") || !encryptedData.contains("iv") || !encryptedData.contains("encrypted_key")) {
                res.status = 400;
                res.set_content(R"({"error":"Missing encrypted_data fields"})", "application/json");
                return;
            }
            if (!rsaObj.contains("n") || !rsaObj.contains("d")) {
                res.status = 400;
                res.set_content(R"({"error":"Missing rsa.n or rsa.d"})", "application/json");
                return;
            }

            u64 n = 0;
            u64 d = 0;
            const std::string nStr = rsaObj["n"].is_string() ? rsaObj["n"].get<std::string>() : std::to_string(rsaObj["n"].get<u64>());
            const std::string dStr = rsaObj["d"].is_string() ? rsaObj["d"].get<std::string>() : std::to_string(rsaObj["d"].get<u64>());
            if (!parseU64(nStr, n) || !parseU64(dStr, d) || n <= 257 || d <= 1) {
                res.status = 400;
                res.set_content(R"({"error":"Invalid RSA n/d"})", "application/json");
                return;
            }

            if (!encryptedData["encrypted_key"].is_array()) {
                res.status = 400;
                res.set_content(R"({"error":"encrypted_key must be array"})", "application/json");
                return;
            }

            std::vector<u8> keyBytes;
            for (const auto& item : encryptedData["encrypted_key"]) {
                std::string cStr = item.is_string() ? item.get<std::string>() : std::to_string(item.get<u64>());
                u64 c = 0;
                if (!parseU64(cStr, c)) {
                    res.status = 400;
                    res.set_content(R"({"error":"Invalid encrypted_key item"})", "application/json");
                    return;
                }
                const u64 m = modPow(c, d, n);
                keyBytes.push_back(static_cast<u8>(m & 0xFF));
            }

            if (keyBytes.size() != 16) {
                res.status = 400;
                res.set_content(R"({"error":"Invalid AES key length"})", "application/json");
                return;
            }

            const std::vector<u8> ivBytes = base64Decode(encryptedData["iv"].get<std::string>());
            const std::vector<u8> payloadBytes = base64Decode(encryptedData["payload"].get<std::string>());
            if (ivBytes.size() != 16) {
                res.status = 400;
                res.set_content(R"({"error":"Invalid IV length"})", "application/json");
                return;
            }

            std::array<u8, 16> key{};
            std::array<u8, 16> iv{};
            std::copy(keyBytes.begin(), keyBytes.end(), key.begin());
            std::copy(ivBytes.begin(), ivBytes.end(), iv.begin());

            const std::vector<u8> plainBytes = aes128CtrTransform(payloadBytes, key, iv);
            const std::string plaintext(plainBytes.begin(), plainBytes.end());
            const json data = json::parse(plaintext);
            res.set_content(safe_json_dump(data), "application/json");
        } catch (const std::exception& e) {
            json error = {
                {"error", "Internal error"},
                {"detail", e.what()}
            };
            res.status = 500;
            res.set_content(safe_json_dump(error), "application/json");
        }
    });

    std::cout << "=== Data Masking + Crypto Service ===" << std::endl;
    std::cout << "Listening on http://0.0.0.0:8080" << std::endl;
    std::cout << "Endpoints:" << std::endl;
    std::cout << "  GET  /health" << std::endl;
    std::cout << "  POST /mask" << std::endl;
    std::cout << "  POST /secure-mask" << std::endl;
    std::cout << "  POST /decrypt" << std::endl;

    svr.listen("0.0.0.0", 8080);
    return 0;
}
