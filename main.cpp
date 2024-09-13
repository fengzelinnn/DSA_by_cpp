#include <iostream>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <map>
#include <cmath>
#include <random>

using namespace std;

// 素性判定函数
bool isPrime(const BIGNUM* n, BN_CTX* ctx) {
    const int ret = BN_check_prime(n, ctx, nullptr);
    if (ret == -1) {
        cerr << "BN_check_prime failed" << endl;
        return false;
    }
    return ret != 0;
}

// 产生160bit长的素数q
BIGNUM* generateQ() {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* q = BN_new();
    BIGNUM* range = BN_new();

    if (!ctx || !q || !range) {
        cerr << "Failed to create BIG NUM or BN_CTX" << endl;
        BN_free(q); BN_free(range); BN_CTX_free(ctx);
        return nullptr;
    }

    // 设定范围 2^160 - 2^159
    BN_set_bit(range, 160);
    BN_set_bit(q, 159);
    BN_sub(range, range, q);

    while (!isPrime(q, ctx)) {
        BN_rand_range(q, range);
        BN_add(q, q, BN_value_one());  // 确保 q > 2^159
    }

    BN_free(range);
    BN_CTX_free(ctx);

    return q;
}

// 生成p使得(p - 1)包含素因子q
BIGNUM* generateP(const BIGNUM* q) {
    const int Ls[] = {512, 576, 640, 704, 768, 832, 896, 960};
    random_device r;
    const int L = Ls[r() % 8];

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p = BN_new();
    BIGNUM* temp = BN_new();
    BIGNUM* one = BN_new();

    if (!ctx || !p || !temp || !one) {
        cerr << "Failed to create BIG NUM or BN_CTX" << endl;
        BN_free(p); BN_free(temp); BN_free(one); BN_CTX_free(ctx);
        return nullptr;
    }

    BN_one(one);

    do {
        BN_rand(temp, L - 160, 0, 0);

        // 计算 p = kq + 1
        BN_mul(p, q, temp, ctx);
        BN_add(p, p, one);
    } while (!isPrime(p, ctx));

    cout << "密钥分量p = ";
    char* p_str = BN_bn2dec(p);
    cout << p_str << endl;
    OPENSSL_free(p_str);

    cout << "p素因子q = " << BN_bn2dec(q) << endl;

    BN_free(temp);
    BN_free(one);
    BN_CTX_free(ctx);

    return p;
}

// 使用openssl中的SHA256实现的hash函数
BIGNUM* SHA_hash(const string &M, const bool flagOfPrint) {
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
        cerr << "Failed to create BIG NUM" << endl;
        return nullptr;
    }

    if (lengthOfHash > INT_MAX) {
        cerr << "Hash length exceeds maximum int value" << endl;
        BN_free(result);
        return nullptr;
    }

    if (!BN_bin2bn(hash, static_cast<int>(lengthOfHash), result)) {
        cerr << "Failed to convert hash to BIG NUM" << endl;
        BN_free(result);
        return nullptr;
    }

    if (char *hex_string = BN_bn2hex(result)) {
        if(flagOfPrint) {
            cout << "h(message) = " << hex_string << endl;
        }
        OPENSSL_free(hex_string);
    } else {
        cerr << "Failed to convert BIG NUM to hex string" << endl;
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
    BIGNUM *e = SHA_hash(M, true);
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

    cout << "\n开始签名>>>" << endl;

    // 计算 r = (g^k mod p) mod q
    if (!BN_mod_exp(temp, g, k, p, ctx) || !BN_mod(r, temp, q, ctx)) {
        // 错误处理
        return {nullptr, nullptr};
    }

    cout << "计算 r = (g^k mod p) mod q, r = " << BN_bn2dec(r) << endl;

    // 计算 k^(-1) mod q
    if (!BN_mod_inverse(k_inv, k, q, ctx)) {
        // 错误处理
        return {nullptr, nullptr};
    }

    // 计算 x*r mod q
    if (!BN_mod_mul(temp, x, r, q, ctx)) {
        // 错误处理
        return {nullptr, nullptr};
    }

    // 计算 e + x*r mod q
    if (!BN_mod_add(temp, e, temp, q, ctx)) {
        // 错误处理
        return {nullptr, nullptr};
    }

    // 计算 s = k^(-1) * (e + x*r) mod q
    if (!BN_mod_mul(s, k_inv, temp, q, ctx)) {
        // 错误处理
        return {nullptr, nullptr};
    }

    cout << "计算 s = k^(-1) * (e + x*r) mod q, s = " << BN_bn2dec(s) << endl;

    BN_free(e);
    BN_free(temp);
    BN_free(k_inv);
    BN_CTX_free(ctx);

    cout << "M的数字签名(r, s) = (" << BN_bn2dec(r) << ", " << BN_bn2dec(s) << ")" << endl;
    return {r, s};
}

bool DSA_verify(const string& M, const pair<BIGNUM*, BIGNUM*>& sign, const BIGNUM* g, const BIGNUM* q, const BIGNUM* y, const BIGNUM* p) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return false;

    bool result = false;

    // 分配所有需要的 BIG NUM
    BIGNUM* e = SHA_hash(M, false);
    BIGNUM* w = BN_new();
    BIGNUM* u1 = BN_new();
    BIGNUM* u2 = BN_new();
    BIGNUM* v = BN_new();
    BIGNUM* temp1 = BN_new();
    BIGNUM* temp2 = BN_new();

    if (!e || !w || !u1 || !u2 || !v || !temp1 || !temp2) {
        goto cleanup;
    }

    cout << "\n开始验签>>>" << endl;

    // 检查签名的有效性
    if (!isSignatureValid(sign.first, sign.second, q)) {
        goto cleanup;
    }

    // 计算 w = s^(-1) mod q
    if (!BN_mod_inverse(w, sign.second, q, ctx)) {
        goto cleanup;
    }

    cout << "计算 w = s^(-1) mod q, w = " << BN_bn2dec(w) << endl;

    // 计算 u1 = (e * w) mod q
    if (!BN_mod_mul(u1, e, w, q, ctx)) {
        goto cleanup;
    }

    cout << "计算 u1 = (e * w) mod q, u1 = " << BN_bn2dec(u1) << endl;

    // 计算 u2 = (r * w) mod q
    if (!BN_mod_mul(u2, sign.first, w, q, ctx)) {
        goto cleanup;
    }

    cout << "计算 u2 = (r * w) mod q, u2 = " << BN_bn2dec(u2) << endl;

    // 计算 v = ((g^u1 * y^u2) mod p) mod q
    if (!BN_mod_exp(temp1, g, u1, p, ctx) ||
        !BN_mod_exp(temp2, y, u2, p, ctx) ||
        !BN_mod_mul(temp1, temp1, temp2, p, ctx) ||
        !BN_mod(v, temp1, q, ctx)) {
        goto cleanup;
        }

    cout << "计算 v = ((g^u1 * y^u2) mod p) mod q, v = " << BN_bn2dec(v) << endl;

    // 检查 v == r
    result = (BN_cmp(v, sign.first) == 0);

    cout << "签名r = " << BN_bn2dec(sign.first) << endl;

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

    BIGNUM* q = generateQ();
    if (!q) BN_free(q);
    BIGNUM* p = generateP(q);

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        cout << "Failed to create BN_CTX" << endl;
        return 1;
    }

    BIGNUM *h = BN_new(), *g = BN_new();
    BIGNUM *x = BN_new(), *y = BN_new(), *k = BN_new();
    const BIGNUM *temp = BN_new();
    BIGNUM *one = BN_new(), *p_minus_1 = BN_new();

    if (!p || !q || !h || !g || !x || !y || !k || !temp || !one || !p_minus_1) {
        cout << "Failed to create BIG NUM" << endl;
        return 1;
    }

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
            cout << "g的种子h = " << h_str << endl;
            OPENSSL_free(h_str);
            break;
        }
    }

    char *g_str = BN_bn2dec(g);
    cout << "密钥分量g = " << g_str << endl;
    OPENSSL_free(g_str);

    // 生成私钥 x (0 < x < q)
    BN_rand_range(x, q);
    char *x_str = BN_bn2dec(x);
    cout << "用户私钥x = " << x_str << endl;
    OPENSSL_free(x_str);

    // 计算公钥 y = g^x mod p
    BN_mod_exp(y, g, x, p, ctx);
    char *y_str = BN_bn2dec(y);
    cout << "用户公钥y = " << y_str << endl;
    OPENSSL_free(y_str);

    // 生成随机数 k (0 < k < q)
    BN_rand_range(k, q);
    char *k_str = BN_bn2dec(k);
    cout << "随机数k = " << k_str << endl;
    OPENSSL_free(k_str);

    // 要签名的消息
    const string message = "This is a test for DSA";

    const string message_fake = "This is a test for RSA";

    // 开始签名和验签过程
    if (const pair<BIGNUM*, BIGNUM*> sign = DSA_sign(x, k, g, p, q, message); sign.first && sign.second) {
        if (DSA_verify(message, sign, g, q, y, p)) {
            cout << "\nr == v, verify OK!" << endl;
        } else {
            cout << "\nr != v, verify FAILED!" << endl;
        }
        if (DSA_verify(message_fake, sign, g, q, y, p)) {
            cout << "\nr == v, verify OK! (this is from a fake message)" << endl;
        } else {
            cout << "\nr != v, verify FAILED! (this is from a fake message)" << endl;
        }
        BN_free(sign.first);
        BN_free(sign.second);
    } else {
        cout << "Signing failed" << endl;
    }

    // 释放分配的内存
    BN_free(q);
    BN_free(p);
    BN_free(h);
    BN_free(g);
    BN_free(x);
    BN_free(y);
    BN_free(k);
    BN_free(one);
    BN_free(p_minus_1);
    BN_free(exp);
    BN_CTX_free(ctx);

    return 0;
}
