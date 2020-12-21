#pragma once
#include <utility>
#include <vector>
#include <string>
#include <exception>
#include <unordered_map>
#include "microecc/uECC.h"
#include <pybind11/pybind11.h>

namespace neo3crypto {
    class ECCException: public std::exception {
    private:
        std::string _message;
    public:
        explicit ECCException(std::string  message) : _message(std::move(message)) {};
        const char* what() const noexcept override {
            return _message.c_str();
        }
    };

    enum class ECCCURVE : unsigned char {
        secp256r1 = 0x0,
        secp256k1 = 0x1
    };

    class ECPoint {
    public:
        ECPoint() = default;
        ECPoint(std::vector<unsigned char> public_key, ECCCURVE curve, bool validate);
        ECPoint(const std::vector<unsigned char>& private_key, ECCCURVE curve);

        void from_bytes(std::vector<unsigned char> compressed_public_key, ECCCURVE curve, bool validate);
        std::vector<unsigned char> encode_point(bool compressed = true);
        std::vector<unsigned char> value;
        std::vector<unsigned char> value_compressed;
        ECCCURVE curve = ECCCURVE::secp256r1;

        friend bool operator<(const ECPoint& lhs, const ECPoint& rhs) { return lhs.compare_to(rhs) < 0; }

        friend bool operator>(const ECPoint& lhs, const ECPoint& rhs) { return rhs < lhs; }

        friend bool operator<=(const ECPoint& lhs, const ECPoint& rhs) { return !(lhs > rhs); }

        friend bool operator>=(const ECPoint& lhs, const ECPoint& rhs) { return !(lhs < rhs); }

        friend bool operator==(const ECPoint& lhs, const ECPoint& rhs) { return lhs.compare_to(rhs) == 0; }

        friend bool operator!=(const ECPoint& lhs, const ECPoint& rhs) { return lhs.compare_to(rhs) != 0; }

        [[nodiscard]] bool is_infinity() const { return _is_infinity; }
    private:
        [[nodiscard]] int compare_to(const ECPoint& other) const;
        bool _is_infinity = false;
    };

    std::vector<unsigned char> to_vector(const pybind11::bytes& input);

    std::vector<unsigned char> sign(const std::vector<unsigned char>& private_key, const std::vector<unsigned char>& message_hash, ECCCURVE curve);
    bool verify(const std::vector<unsigned char>& signature, const std::vector<unsigned char>& message_hash, ECPoint public_key);

    }