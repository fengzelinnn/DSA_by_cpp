#include <iostream>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <map>
#include <cmath>
#include <random>

using namespace std;

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
    random_device r;
    const int L = Ls[r() % 8];

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
BIGNUM* elementOfBigPrime(BIGNUM* p) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM *q = BN_new(), *r_bn = BN_new(), *range = BN_new(), *temp = BN_new();
    BIGNUM *lowRange = BN_new(), *highRange = BN_new(), *temp2 = BN_new();

    if (!ctx || !q || !r_bn || !range || !temp || !lowRange || !highRange || !temp2) {
        // 错误处理
        std::cerr << "Failed to create BIG NUM or BN_CTX" << std::endl;
        // 释放已分配的内存
        BN_free(q); BN_free(r_bn); BN_free(range); BN_free(temp);
        BN_free(lowRange); BN_free(highRange); BN_free(temp2);
        BN_CTX_free(ctx);
        return nullptr;
    }

    // 设置范围
    BN_set_bit(lowRange, 159);
    BN_set_bit(highRange, 160);
    BN_sub(range, highRange, lowRange);

    // 使用更好的随机数生成器
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned long long> dis;

    BIGNUM* one = BN_new();
    BN_one(one);
    BN_sub(p, p, one);
    cout << "current p-1:" << BN_bn2dec(p) << endl;

    while (true) {
        // 生成随机数
        const unsigned long long r = dis(gen);
        BN_set_word(r_bn, r);

        // 计算 q = lowRange + (r_bn % range)
        BN_mod(temp, r_bn, range, ctx);
        BN_add(q, lowRange, temp);

        // 检查 q 是否为素数且是否为 p - 1 的因子
        if (isPrime(q, ctx) && BN_mod(temp2, p, q, ctx) && BN_is_zero(temp2)) {
            char *q_str = BN_bn2dec(q);
            std::cout << "密钥分量q = " << q_str << std::endl;
            OPENSSL_free(q_str);
            break;
        }

        char *q_str = BN_bn2dec(q);
        cout << "current q:" << q_str << endl;
        OPENSSL_free(q_str);
    }

    // 清理
    BN_free(r_bn); BN_free(range); BN_free(temp);
    BN_free(lowRange); BN_free(highRange); BN_free(temp2); BN_free(one);
    BN_CTX_free(ctx);

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
    if (!result) {
        std::cerr << "Failed to create BIG NUM" << std::endl;
        return nullptr;
    }

    if (lengthOfHash > INT_MAX) {
        std::cerr << "Hash length exceeds maximum int value" << std::endl;
        BN_free(result);
        return nullptr;
    }

    if (!BN_bin2bn(hash, static_cast<int>(lengthOfHash), result)) {
        std::cerr << "Failed to convert hash to BIG NUM" << std::endl;
        BN_free(result);
        return nullptr;
    }

    if (char *hex_string = BN_bn2hex(result)) {
        std::cout << "h(message): " << hex_string << std::endl;
        OPENSSL_free(hex_string);
    } else {
        std::cerr << "Failed to convert BIG NUM to hex string" << std::endl;
    }

    return result;
}

bool isSignatureValid(const BIGNUM* r, const BIGNUM* s, const BIGNUM* q) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return false;

    BIGNUM *zero = BN_new();
    if (!zero) {
        BN_CTX_free(ctx);
        return false;
    }
    BN_zero(zero);  // 设置为0

    const bool isValid = (BN_cmp(r, zero) > 0) &&  // 0 < r
                         (BN_cmp(r, q) < 0) &&     // r < q
                         (BN_cmp(s, zero) > 0) &&  // 0 < s
                         (BN_cmp(s, q) < 0);       // s < q

    BN_free(zero);
    BN_CTX_free(ctx);

    return isValid;
}

pair<BIGNUM*, BIGNUM*> DSA_sign(const BIGNUM* x, const BIGNUM* k, const BIGNUM* g, const BIGNUM* p, const BIGNUM* q, const string& M) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return {nullptr, nullptr};

    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *e = SHA_hash(M);
    BIGNUM *temp = BN_new();
    BIGNUM *k_inv = BN_new();

    if (!r || !s || !e || !temp || !k_inv) {
        // 错误处理
        BN_CTX_free(ctx);
        BN_free(r);
        BN_free(s);
        BN_free(e);
        BN_free(temp);
        BN_free(k_inv);
        return {nullptr, nullptr};
    }

    // 计算 r = (g^k mod p) mod q
    if (!BN_mod_exp(temp, g, k, p, ctx) || !BN_mod(r, temp, q, ctx)) {
        // 错误处理
        // ...
        return {nullptr, nullptr};
    }

    // 计算 k^(-1) mod q
    if (!BN_mod_inverse(k_inv, k, q, ctx)) {
        // 错误处理
        // ...
        return {nullptr, nullptr};
    }

    // 计算 x*r mod q
    if (!BN_mod_mul(temp, x, r, q, ctx)) {
        // 错误处理
        // ...
        return {nullptr, nullptr};
    }

    // 计算 e + x*r mod q
    if (!BN_mod_add(temp, e, temp, q, ctx)) {
        // 错误处理
        // ...
        return {nullptr, nullptr};
    }

    // 计算 s = k^(-1) * (e + x*r) mod q
    if (!BN_mod_mul(s, k_inv, temp, q, ctx)) {
        // 错误处理
        // ...
        return {nullptr, nullptr};
    }

    BN_free(e);
    BN_free(temp);
    BN_free(k_inv);
    BN_CTX_free(ctx);

    cout << "M的数字签名(r, s): (" << r << ", " << s << ")" << endl;
    return {r, s};
}

bool DSA_verify(const string& M, const pair<BIGNUM*, BIGNUM*>& sign, const BIGNUM* g, const BIGNUM* q, const BIGNUM* y, const BIGNUM* p) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return false;

    bool result = false;

    // 分配所有需要的 BIG NUM
    BIGNUM* e = SHA_hash(M);
    BIGNUM* w = BN_new();
    BIGNUM* u1 = BN_new();
    BIGNUM* u2 = BN_new();
    BIGNUM* v = BN_new();
    BIGNUM* temp1 = BN_new();
    BIGNUM* temp2 = BN_new();

    if (!e || !w || !u1 || !u2 || !v || !temp1 || !temp2) {
        goto cleanup;
    }

    // 检查签名的有效性
    if (!isSignatureValid(sign.first, sign.second, q)) {
        goto cleanup;
    }

    // 计算 w = s^(-1) mod q
    if (!BN_mod_inverse(w, sign.second, q, ctx)) {
        goto cleanup;
    }

    // 计算 u1 = (e * w) mod q
    if (!BN_mod_mul(u1, e, w, q, ctx)) {
        goto cleanup;
    }

    // 计算 u2 = (r * w) mod q
    if (!BN_mod_mul(u2, sign.first, w, q, ctx)) {
        goto cleanup;
    }

    // 计算 v = ((g^u1 * y^u2) mod p) mod q
    if (!BN_mod_exp(temp1, g, u1, p, ctx) ||
        !BN_mod_exp(temp2, y, u2, p, ctx) ||
        !BN_mod_mul(temp1, temp1, temp2, p, ctx) ||
        !BN_mod_sub(v, temp1, q, nullptr, ctx)) {
        goto cleanup;
        }

    // 检查 v == r
    result = (BN_cmp(v, sign.first) == 0);

    cleanup:
        // 释放所有分配的内存
        BN_free(e);
        BN_free(w);
        BN_free(u1);
        BN_free(u2);
        BN_free(v);
        BN_free(temp1);
        BN_free(temp2);
        BN_CTX_free(ctx);

    return result;
}

int main() {
    if (const BN_CTX *ctx = BN_CTX_new(); !ctx) return 0;
    BIGNUM* p = bigPrimeBuilder();
    BIGNUM* p_temp = p;
    const BIGNUM* q = elementOfBigPrime(p_temp);

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        std::cout << "Failed to create BN_CTX" << std::endl;
        return 1;
    }

    BIGNUM *h = BN_new(), *g = BN_new();
    BIGNUM *x = BN_new(), *y = BN_new(), *k = BN_new();
    const BIGNUM *temp = BN_new();
    BIGNUM *one = BN_new(), *p_minus_1 = BN_new();

    if (!p || !q || !h || !g || !x || !y || !k || !temp || !one || !p_minus_1) {
        std::cout << "Failed to create BIG NUM" << std::endl;
        return 1;
    }

    // 假设 p 和 q 已经被正确初始化
    // BN_hex2bn(&p, "your_p_value_in_hex");
    // BN_hex2bn(&q, "your_q_value_in_hex");

    BN_one(one);
    BN_sub(p_minus_1, p, one);

    // 计算 (p-1)/q
    BIGNUM *exp = BN_new();
    BN_div(exp, nullptr, p_minus_1, q, ctx);

    // 生成 g
    while (true) {
        BN_rand_range(h, p_minus_1);
        BN_add(h, h, one);
        BN_mod_exp(g, h, exp, p, ctx);
        if (BN_cmp(g, one) > 0) {
            char *h_str = BN_bn2dec(h);
            std::cout << "g的种子h: " << h_str << std::endl;
            OPENSSL_free(h_str);
            break;
        }
    }

    char *g_str = BN_bn2dec(g);
    std::cout << "密钥分量g: " << g_str << std::endl;
    OPENSSL_free(g_str);

    // 生成私钥 x (0 < x < q)
    BN_rand_range(x, q);
    char *x_str = BN_bn2dec(x);
    std::cout << "用户私钥x: " << x_str << std::endl;
    OPENSSL_free(x_str);

    // 计算公钥 y = g^x mod p
    BN_mod_exp(y, g, x, p, ctx);
    char *y_str = BN_bn2dec(y);
    std::cout << "用户公钥y: " << y_str << std::endl;
    OPENSSL_free(y_str);

    // 生成随机数 k (0 < k < q)
    BN_rand_range(k, q);
    char *k_str = BN_bn2dec(k);
    std::cout << "随机数k: " << k_str << std::endl;
    OPENSSL_free(k_str);

    const string message = "This is a test for DSA";

    if (const pair<BIGNUM*, BIGNUM*> sign = DSA_sign(x, k, g, p, q, message); DSA_verify(message, sign, g, q, y, p) == true) {
        cout << "verify OK" << endl;
    } else {
        cout << "verify FAILED" << endl;
    }

    return 0;
}
