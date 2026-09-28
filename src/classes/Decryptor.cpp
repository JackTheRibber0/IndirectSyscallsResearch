/*
 * Copyright (c) 2026 JackTheRibber0 - https://github.com/JackTheRibber0
 * Licensed under the Apache License, Version 2.0
 *
 * LEGAL DISCLAIMER:
 * This C++ source code and the resulting binary are intended strictly for
 * educational purposes, academic research, and authorized Red Team operations.
 * The author assumes no liability for unauthorized or malicious use.
 */

#include "Miscellaneous.h"

#include "Decryptor.h"

using namespace aes;

void Aes256Decryptor::handleErrors() const
{
    ERR_print_errors_fp(stderr);
    throw std::runtime_error("OpenSSL Error");
}

std::string Aes256Decryptor::decryptAsString(const std::vector<uint8_t>& encodedVec, size_t& outLen) const
{
    auto decrypted = decrypt(encodedVec, outLen);

    std::string decryptedString(reinterpret_cast<const char*>(decrypted.get()), outLen);

    return decryptedString;
}

std::unique_ptr<UCHAR[]> Aes256Decryptor::decrypt(const std::vector<uint8_t>& encodedVec, size_t& outLen) const
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_.data(), iv_.data())) handleErrors();

    std::vector<UCHAR> decryptedBuff(encodedVec.size());
    int32_t len = 0;
    int32_t decryptedLen = 0;

    if (1 != EVP_DecryptUpdate(ctx, decryptedBuff.data(), &len, encodedVec.data(), encodedVec.size())) handleErrors();
    decryptedLen = len;

    if (1 != EVP_DecryptFinal_ex(ctx, decryptedBuff.data() + len, &len)) handleErrors();
    decryptedLen += len;

    EVP_CIPHER_CTX_free(ctx);

    auto decryptedBuffArr = std::make_unique<UCHAR[]>(decryptedLen);
    std::memcpy(decryptedBuffArr.get(), decryptedBuff.data(), decryptedLen);

    outLen = decryptedLen;

    return decryptedBuffArr;
}

std::vector<uint8_t> Aes256Decryptor::encrypt(std::string_view plainText) const
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_.data(), iv_.data())) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }

    std::vector<uint8_t> encryptedBuff(plainText.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int32_t len = 0;
    int32_t encryptedLen = 0;

    if (1 != EVP_EncryptUpdate(ctx,
        encryptedBuff.data(),
        &len,
        reinterpret_cast<const UCHAR*>(plainText.data()),
        static_cast<int>(plainText.size())))
    {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }
    encryptedLen = len;

    if (1 != EVP_EncryptFinal_ex(ctx, encryptedBuff.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }
    encryptedLen += len;

    EVP_CIPHER_CTX_free(ctx);

    encryptedBuff.resize(encryptedLen);

    std::cout << "\nstd::vector<uint8_t> encryptedVec = { ";
    std::cout << std::hex << std::uppercase; 

    for (size_t i = 0; i < encryptedBuff.size(); ++i) {
        std::cout << "0x" << std::setw(2) << std::setfill('0') << static_cast<int>(encryptedBuff[i]);
        
        if (i < encryptedBuff.size() - 1) {
            std::cout << ", ";
        }

        if ((i + 1) % 12 == 0 && i < encryptedBuff.size() - 1) {
            std::cout << "\n  ";
        }
    }

    std::cout << std::dec << " };\n" << std::endl;

    return encryptedBuff;
}