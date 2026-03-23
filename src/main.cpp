#include <iostream>
#include <string>
#include <algorithm>
#include "httplib.h"
#include "json.hpp"

using json = nlohmann::json;

static std::string safe_json_dump(const json& value) {
    return value.dump(-1, ' ', false, json::error_handler_t::replace);
}

// ============================================================
// Masking Functions
// ============================================================

// Helper for UTF-8 character byte length
inline size_t utf8_char_length(unsigned char c) {
    if ((c & 0x80) == 0) return 1;
    if ((c & 0xE0) == 0xC0) return 2;
    if ((c & 0xF0) == 0xE0) return 3;
    if ((c & 0xF8) == 0xF0) return 4;
    return 1;
}

// Get the number of UTF-8 characters in a string
size_t utf8_length(const std::string& str) {
    size_t len = 0;
    size_t i = 0;
    while (i < str.length()) {
        i += utf8_char_length(static_cast<unsigned char>(str[i]));
        len++;
    }
    return len;
}

// Safely get a substring of UTF-8 characters
std::string utf8_substr(const std::string& str, size_t char_start, size_t char_len) {
    size_t byte_pos = 0;
    size_t chars_seen = 0;
    
    // Find start byte
    while (byte_pos < str.length() && chars_seen < char_start) {
        byte_pos += utf8_char_length(static_cast<unsigned char>(str[byte_pos]));
        chars_seen++;
    }
    
    size_t start_byte = byte_pos;
    chars_seen = 0;
    
    // Find end byte
    while (byte_pos < str.length() && chars_seen < char_len) {
        byte_pos += utf8_char_length(static_cast<unsigned char>(str[byte_pos]));
        chars_seen++;
    }
    
    return str.substr(start_byte, byte_pos - start_byte);
}

/**
 * Mask a name: keep first 2 and last 2 chars, replace middle with ***
 * "Nguyen Van A" -> "Ng***n A"
 * Short names (<=4 chars) -> first char + ***
 */
std::string maskName(const std::string& name) {
    if (name.empty()) return name;

    size_t len = utf8_length(name);
    if (len <= 4) {
        return utf8_substr(name, 0, 1) + "***";
    }

    // Keep first 2 and last 2 characters
    std::string result = utf8_substr(name, 0, 2) + "***" + utf8_substr(name, len - 2, 2);
    return result;
}

/**
 * Mask phone: keep first 3 and last 3 digits, replace middle with ****
 * "0912345678" -> "091****678"
 */
std::string maskPhone(const std::string& phone) {
    if (phone.length() <= 6) return "***";

    std::string digits;
    for (char c : phone) {
        if (std::isdigit(c) || c == '+') digits += c;
    }

    if (digits.length() <= 6) return "***";

    return digits.substr(0, 3) + "****" + digits.substr(digits.length() - 3);
}

/**
 * Mask email: keep first 3 chars of local part, mask rest, keep domain
 * "receiver@example.com" -> "rec****@example.com"
 */
std::string maskEmail(const std::string& email) {
    size_t atPos = email.find('@');
    if (atPos == std::string::npos) return "***";

    std::string localPart = email.substr(0, atPos);
    std::string domain = email.substr(atPos); // includes @

    size_t localLen = utf8_length(localPart);

    if (localLen <= 3) {
        return utf8_substr(localPart, 0, 1) + "****" + domain;
    }

    return utf8_substr(localPart, 0, 3) + "****" + domain;
}

/**
 * Mask address: keep first 5 chars, mask middle portion, keep last 8 chars
 * "123 Duong ABC, TP.HCM" -> "123 D****, TP.HCM"
 */
std::string maskAddress(const std::string& address) {
    if (address.empty()) return address;

    size_t len = utf8_length(address);
    if (len <= 10) {
        return utf8_substr(address, 0, 3) + "****";
    }

    // Keep first 5 chars and last 8 chars
    size_t keepStart = 5;
    size_t keepEnd = 8;

    if (keepStart + keepEnd >= len) {
        return utf8_substr(address, 0, 3) + "****";
    }

    return utf8_substr(address, 0, keepStart) + "****" + utf8_substr(address, len - keepEnd, keepEnd);
}

// ============================================================
// Main: HTTP Server
// ============================================================

int main() {
    httplib::Server svr;

    // CORS middleware
    svr.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) -> httplib::Server::HandlerResponse {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");

        if (req.method == "OPTIONS") {
            res.status = 204;
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // Health check
    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        json response = {
            {"status", "ok"},
            {"service", "data-masking"},
            {"version", "1.0.0"}
        };
        res.set_content(safe_json_dump(response), "application/json");
    });

    // POST /mask - Main masking endpoint
    svr.Post("/mask", [](const httplib::Request& req, httplib::Response& res) {
        try {
            json body = json::parse(req.body);

            // Mask sensitive fields if they exist
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

            res.set_content(safe_json_dump(body), "application/json");

        } catch (const json::parse_error& e) {
            json error = {
                {"error", "Invalid JSON"},
                {"detail", e.what()}
            };
            res.status = 400;
            res.set_content(safe_json_dump(error), "application/json");
        } catch (const std::exception& e) {
            json error = {
                {"error", "Internal error"},
                {"detail", e.what()}
            };
            res.status = 500;
            res.set_content(safe_json_dump(error), "application/json");
        }
    });

    std::cout << "=== Data Masking Service ===" << std::endl;
    std::cout << "Listening on http://0.0.0.0:8080" << std::endl;
    std::cout << "Endpoints:" << std::endl;
    std::cout << "  GET  /health  - Health check" << std::endl;
    std::cout << "  POST /mask    - Mask sensitive data" << std::endl;

    svr.listen("0.0.0.0", 8080);

    return 0;
}
