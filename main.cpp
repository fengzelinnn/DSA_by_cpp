#include <iostream>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <map>
#include <cstdlib>

using namespace std;

//TODO (1): adapt all operators;
//TODO (2): finish the de_mod function

// Prime judge using OpenSSL
bool isPrime(const BIGNUM* n, BN_CTX* ctx) {
    BIGNUM* r = BN_new();
    if (!r) {
        std::cerr << "Failed to create BIG NUM" << std::endl;
        return false;
    }

    const int ret = BN_check_prime(n, ctx, nullptr);

    BN_free(r);
    if (ret == -1) {
        std::cerr << "BN_check_prime failed" << std::endl;
        return false;
    }
    return ret != 0;
}

// Product a prime in (2^(L-1), 2^L), L is a multiple of 64 which between 512 and 1024.
BIGNUM* bigPrimeBuilder() {
    const int Ls[] = {512, 576, 640, 704, 768, 832, 896, 960};
    const int L = Ls[rand() % 8];

    BIGNUM* p = BN_new();
    BIGNUM* range = BN_new();
    BN_CTX* ctx = BN_CTX_new();

    if (!p || !range || !ctx) {
        std::cerr << "Failed to create BIG NUM or BN_CTX" << std::endl;
        return nullptr;
    }

    // Set range to 2^(L-1)
    BN_set_bit(range, L - 1);

    // Generate random number and add to 2^(L-1)
    BN_rand_range(p, range);
    BN_add(p, p, range);

    while (!isPrime(p, ctx)) {
        BN_rand_range(p, range);
        BN_add(p, p, range);
    }

    std::cout << "密钥分量p = ";
    char* p_str = BN_bn2dec(p);
    std::cout << p_str << std::endl;
    OPENSSL_free(p_str);

    BN_free(range);
    BN_CTX_free(ctx);

    return p;
}

//find an element of p - 1 which is a prime
BIGNUM* elementOfBigPrime(const BIGNUM* n) {
    BN_CTX* ctx = BN_CTX_new();
    const long double lwoRange = pow(2, 159);
    const long double highRange = pow(2, 160);
    BIGNUM* q = BN_new();
    while (true) {
        long double r = rand();
        q = lwoRange + r % (highRange - lwoRange);

        if (isPrime(q, ctx) && n % q == 0) {
            break;
        }
    }
    BN_CTX_free(ctx);
    cout << "密钥分量q = " << q << endl;
    return q;
}

//T ODO: finish the hash function
BIGNUM* SHA_hash(const string &M) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return nullptr;
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr)) {
        EVP_MD_CTX_free(ctx);
        return nullptr;
    }
    if (!EVP_DigestUpdate(ctx, M.c_str(), M.length())) {
        EVP_MD_CTX_free(ctx);
        return nullptr;
    }
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    if (!EVP_DigestFinal_ex(ctx, hash, &lengthOfHash)) {
        EVP_MD_CTX_free(ctx);
        return nullptr;
    }
    EVP_MD_CTX_free(ctx);
    BIGNUM* result = BN_new();
    for(int i = 0; i < 8 && i < lengthOfHash; i++) {
        result = (result << 8) + hash[i];
    }
    cout << "h(message):" << result << endl;
    return result;
}

pair<int, int> DSA_sign(const long k, const int g, const BIGNUM* p, const BIGNUM* q, const string& M) {
    BIGNUM* e = SHA_hash(M);
    int r = (pow(g, k) % p) % q;
    int s = 0;
    pair<int, int> DS = make_pair(r, s);
    return DS;
}

bool DSA_verify(const string& M, const pair<int, int> &sign, const int g, const BIGNUM* q, const long y, const BIGNUM* p) {
    if (0 < sign.first < q && 0 < sign.second < q) {
        BIGNUM *e = SHA_hash(M);
        constexpr int w = 0;
        const long long u1 = (e * w) % q;
        const long long u2 = (sign.first * w) % q;
        if (const int v = ((pow(g, u1) * pow(y, u2)) % p) % q; v == sign.first) {
            return true;
        }
    }
    return false;
}

int main() {
    if (const BN_CTX *ctx = BN_CTX_new(); !ctx) return 0;
    const BIGNUM* p = bigPrimeBuilder();
    const BIGNUM* q = elementOfBigPrime(p);

    int h = 0;
    while(true) {
        h = rand() % (p - 1) + 1;
        if (pow(h, (p - 1) / q) % p > 1) {
            cout << "g的种子h:" << h << endl;
            break;
        }
    }

    int g = pow(h, (p - 1) / q) % p;
    cout << "密钥分量g:" <<g << endl;

    long x = rand() % q;
    cout << "用户私钥x：" << x << endl;

    long y = pow(g, x) % p;
     cout << "用户公钥y：" << y << endl;

    const long k = rand() % q;
    cout << "随机数k：" << k << endl;

    const string message = "This is a test for DSA";

    if (const pair<int, int> sign = DSA_sign(k, g, p, q, message); DSA_verify(message, sign, g, q, y, p) == true) {
        cout << "verify OK" << endl;
    } else {
        cout << "verify FAILED" << endl;
    }

    return 0;
}
