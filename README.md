# DSA (Digital Signature Algorithm) 实现程序文档

## 1. 程序概述

这个程序实现了数字签名算法DSA (Digital Signature Algorithm)。DSA是一种利用离散对数难题来实现数字签名的算法，广泛应用于数字证书等领域。该程序包括以下主要功能:

- 生成DSA密钥对，包括公钥和私钥。
- 使用私钥对给定消息进行数字签名。
- 使用公钥验证签名的正确性。

程序主要包括以下几个部分:

1. 辅助函数，如素性检测、大素数生成等。
2. DSA签名和验证函数的实现。
3. 主函数，用于演示DSA签名和验证过程。

## 2. 辅助函数

### 2.1 素性检测

```cpp
bool isPrime(const BIGNUM* n, BN_CTX* ctx)
```

这个函数使用OpenSSL库中的`BN_check_prime`函数检测给定的大数`n`是否为素数。它需要一个`BN_CTX`上下文对象作为参数。函数返回`true`表示`n`是素数，否则返回`false`。

### 2.2 生成素数q

```cpp
BIGNUM* generateQ()
```

该函数用于生成DSA算法所需的160位素数q。它首先创建一个范围在2^159到2^160之间的范围，然后在该范围内随机选择一个数，检测它是否为素数。如果不是，则继续随机选择，直到找到一个素数为止。最后返回生成的素数q。

### 2.3 生成素数p

```cpp
BIGNUM* generateP(const BIGNUM* q)
```

该函数用于生成一个大素数p，使得p-1能被q整除。它首先随机选择一个介于512到1024之间的64的倍数作为p的位长度L。然后随机选择一个L-160位的数k，计算p=kq+1。如果计算出的p不是素数，则继续随机选择k，直到p为素数为止。最后返回生成的大素数p。

### 2.4 哈希函数

```cpp
BIGNUM* SHA_hash(const string &M, const bool flagOfPrint)
```

该函数使用OpenSSL库中的SHA-256算法计算给定字符串M的哈希值。它返回一个BIGNUM对象，表示哈希值。如果`flagOfPrint`为`true`，则会在控制台输出哈希值的十六进制表示。

### 2.5 签名有效性检查

```cpp
bool isSignatureValid(const BIGNUM* r, const BIGNUM* s, const BIGNUM* q)
```

该函数检查DSA签名(r,s)的有效性。根据DSA算法的要求，一个有效的签名必须满足0<r<q和0<s<q。函数返回`true`表示签名有效，否则返回`false`。

## 3. DSA签名和验证

### 3.1 DSA签名函数

```cpp
pair<BIGNUM*, BIGNUM*> DSA_sign(const BIGNUM* x, const BIGNUM* k, const BIGNUM* g, const BIGNUM* p, const BIGNUM* q, const string& M)
```

该函数实现了DSA的签名算法。它接受以下参数:

- `x`: 用户的私钥
- `k`: 随机数，用于签名
- `g`: DSA算法所需的公共参数
- `p`: DSA算法所需的大素数
- `q`: DSA算法所需的160位素数
- `M`: 要签名的消息字符串

函数按照DSA算法的步骤计算出签名(r,s)，并返回这个签名对。如果在计算过程中出现错误，则返回`{nullptr, nullptr}`。

### 3.2 DSA验证函数

```cpp
bool DSA_verify(const string& M, const pair<BIGNUM*, BIGNUM*>& sign, const BIGNUM* g, const BIGNUM* q, const BIGNUM* y, const BIGNUM* p)
```

该函数实现了DSA的验证算法。它接受以下参数:

- `M`: 要验证的消息字符串
- `sign`: 要验证的签名对(r,s)
- `g`: DSA算法所需的公共参数
- `q`: DSA算法所需的160位素数
- `y`: 用户的公钥
- `p`: DSA算法所需的大素数

函数按照DSA算法的步骤验证签名的正确性。如果签名有效，则返回`true`，否则返回`false`。

## 4. 主函数

主函数`main`演示了DSA签名和验证的完整过程。它首先调用`generateQ`和`generateP`函数生成DSA算法所需的参数q和p。然后，它生成DSA的其他参数g、用户的私钥x和公钥y以及随机数k。

接下来，程序调用`DSA_sign`函数对给定的消息进行签名，得到签名对(r,s)。然后，它调用`DSA_verify`函数验证这个签名的正确性。

为了演示DSA算法的安全性，程序还尝试使用一个伪造的消息来验证签名。结果应该显示，使用正确的消息时验证成功，而使用伪造的消息时验证失败。

最后，程序释放所有分配的内存，以避免内存泄漏。

## 5. 程序输出

程序的输出包括以下内容:

1. 生成的DSA参数q、p和g。
2. 生成的用户私钥x和公钥y。
3. 用于签名的随机数k。
4. 签名过程中的中间计算结果，如r和s的值。
5. 验证过程中的中间计算结果，如w、u1、u2和v的值。
6. 使用正确消息和伪造消息进行验证的结果。

---

注意：本程序使用了OpenSSL库来进行大数运算和哈希计算。在编译和运行程序时，请确保正确链接了OpenSSL库。
