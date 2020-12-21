#include "ecc.h"
#include <utility>
#include <unordered_map>
#include "microecc/uECC.h"

namespace neo3crypto {
    std::vector<unsigned char> to_vector(const pybind11::bytes& input) {
        auto size = static_cast<size_t>(PYBIND11_BYTES_SIZE(input.ptr()));
        const auto *data = reinterpret_cast<const unsigned char*>(PYBIND11_BYTES_AS_STRING(input.ptr()));
        return std::vector<unsigned char>(data, data + size);
    }

    static uECC_Curve get_uecc_curve(const ECCCURVE curve) {
        switch (curve) {
            case ECCCURVE::secp256r1:
                return uECC_secp256r1();
            case ::neo3crypto::ECCCURVE::secp256k1:
                return uECC_secp256k1();
            default:
                throw ECCException("Unsupported curve");
        }
    }

    ECPoint::ECPoint(std::vector<unsigned char> public_key, ECCCURVE curve_, bool validate) : curve{curve_} {
        if (public_key.empty())
            throw ECCException("Public key has no data");
        auto internal_curve = get_uecc_curve(curve_);
        auto curve_size = uECC_curve_private_key_size(internal_curve);

        value = std::vector<unsigned char>(curve_size * 2, 0);

        if (public_key.size() == 1 && public_key[0] == 0) {
            _is_infinity = true;
            value_compressed = std::vector<unsigned char>(curve_size * 2, 0);
            return;
        }

        if (public_key[0] == 0x2 || public_key[0] == 0x3) {
            if (public_key.size() != (curve_size + 1)) {
                throw ECCException("Incorrect public key length for specified curve.");
            }
            value_compressed = std::move(public_key);

            uECC_decompress(value_compressed.data(), value.data(), internal_curve);
        } else if (public_key[0] == 0x4) {
            // key is in uncompressed format, store it without the prefix
            std::copy(public_key.begin() + 1, public_key.end(), value.begin());
            value_compressed = std::vector<unsigned char>(curve_size + 1, 0);
            uECC_compress(value.data(), value_compressed.data(), internal_curve);
        }

        if (validate) {
            if (!uECC_valid_public_key(value.data(), internal_curve)) {
                throw ECCException("Failed public key validation");
            }
        }
    }

    ECPoint::ECPoint(const std::vector<unsigned char>& private_key, ECCCURVE curve_) : curve{curve_} {
        auto internal_curve = get_uecc_curve(curve);
        int curve_size = uECC_curve_private_key_size(internal_curve);

        if (curve_size != private_key.size()) {
            throw ECCException("Incorrect private key length for specified curve");
        }

        value = std::vector<unsigned char>(curve_size * 2);

        if (!uECC_compute_public_key(private_key.data(), value.data() , internal_curve)) {
            throw ECCException("Failed public key computation");
        }

        value_compressed = std::vector<unsigned char>(curve_size + 1);
        uECC_compress(value.data(), value_compressed.data(), internal_curve);
    }

    int ECPoint::compare_to(const ECPoint& other) const {
        auto half = value.size() / 2;
        auto x_smaller = std::lexicographical_compare(value.begin(), value.begin() + half, other.value.begin(), other.value.begin() + half);
        if (x_smaller)
            return -1;
        auto x_bigger = std::lexicographical_compare(other.value.begin(), other.value.begin() + half, value.begin(), value.begin() + half);
        if (x_bigger)
            return 1;
        // x is equal, so check y
        auto y_smaller = std::lexicographical_compare(value.begin() + half, value.end(), other.value.begin() + half, other.value.end());
        if (y_smaller)
            return -1;
        auto y_bigger = std::lexicographical_compare(other.value.begin() + half, other.value.end(), value.begin() + half, value.end());
        if (y_bigger)
            return 1;
        return 0;
    }

    std::vector<unsigned char> ECPoint::encode_point(bool compressed) {
        if (_is_infinity) {
            return std::vector<unsigned char>(1,0);
        }
        if (compressed)
            return value_compressed;
        std::vector<unsigned char> uncompressed(value.size() + 1);
        uncompressed[0] = 0x4;
        std::copy(value.begin(), value.end(), uncompressed.begin()+1);
        return uncompressed;
    }

    void ECPoint::from_bytes(std::vector<unsigned char> public_key, ECCCURVE curve_, bool validate) {
        if (public_key.empty())
            throw ECCException("Public key has no data");

        auto internal_curve = get_uecc_curve(curve_);
        auto curve_size = uECC_curve_private_key_size(internal_curve);

        value = std::vector<unsigned char>(curve_size * 2, 0);

        if (public_key.size() == 1 && public_key[0] == 0) {
            _is_infinity = true;
            value_compressed = std::vector<unsigned char>(curve_size * 2, 0);
            return;
        }

        _is_infinity = false;
        if (public_key[0] == 0x2 || public_key[0] == 0x3) {
            if (public_key.size() != (curve_size + 1)) {
                throw ECCException("Incorrect public key length for specified curve.");
            }
            value_compressed = std::move(public_key);

            uECC_decompress(value_compressed.data(), value.data(), internal_curve);
        } else if (public_key[0] == 0x4) {
            // key is in uncompressed format, store it without the prefix
            std::copy(public_key.begin() + 1, public_key.end(), value.begin());
            value_compressed = std::vector<unsigned char>(curve_size + 1, 0);
            uECC_compress(value.data(), value_compressed.data(), internal_curve);
        }

        if (validate) {
            if (!uECC_valid_public_key(value.data(), internal_curve)) {
                throw ECCException("Failed public key validation");
            }
        }
    }

    std::vector<unsigned char> sign(const std::vector<unsigned char>& private_key, const std::vector<unsigned char>& message_hash, ECCCURVE curve) {
        auto internal_curve = get_uecc_curve(curve);
        auto curve_size = uECC_curve_private_key_size(internal_curve);
        if (private_key.size() != curve_size)
            throw ECCException("Incorrect private key length for specified curve.");

        std::vector<unsigned char> signature(curve_size * 2);
        uECC_sign(private_key.data(), message_hash.data(), message_hash.size(), signature.data(), internal_curve);
        return signature;
    }

    bool verify(const std::vector<unsigned char>& signature, const std::vector<unsigned char>& message_hash,
                       ECPoint public_key) {
        auto internal_curve = get_uecc_curve(public_key.curve);
        auto curve_size = uECC_curve_private_key_size(internal_curve);
        if (signature.size() != curve_size * 2)
            throw ECCException("Incorrect signature length for specified curve.");
        auto result = uECC_verify(public_key.value.data(),
                                  message_hash.data(),
                                  message_hash.size(),
                                  signature.data(),
                                  internal_curve);
        return static_cast<bool>(result);
    }
}
