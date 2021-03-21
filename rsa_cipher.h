#ifndef RSA_CIPHER_H_
#define RSA_CIPHER_H_

#include <vector>
#include <cinttypes>
#include <string>
#include <map>

extern std::map<wchar_t, uint8_t> alpha;
extern std::map<uint8_t, wchar_t> reverse_alpha;

class RsaCipher {
public:
    RsaCipher();

    std::vector<uint32_t> Encrypt(const std::wstring& __message);
    std::wstring Decrypt(const std::vector<uint32_t>& __message);

private:
    uint32_t modulus_{};
    uint32_t private_key_{};
    uint32_t public_key_{};
};

#endif // RSA_CIPHER_H_