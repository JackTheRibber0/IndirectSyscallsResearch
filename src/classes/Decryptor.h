/*
 * Copyright (c) 2026 JackTheRibber0 - https://github.com/JackTheRibber0
 * Licensed under the Apache License, Version 2.0
 *
 * LEGAL DISCLAIMER:
 * This C++ source code and the resulting binary are intended strictly for
 * educational purposes, academic research, and authorized Red Team operations.
 * The author assumes no liability for unauthorized or malicious use.
 */

#pragma once

#include <cstring>
#include <vector>
#include <iostream>
#include <iomanip>

#include <memory>
#include <Windows.h>

#define OPENSSL_STATIC

#include <openssl/evp.h>
#include <openssl/err.h>

namespace aes
{
    // reusable snippet from my old project
    class Aes256Decryptor 
    {
    public:
        Aes256Decryptor(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv): key_(key), iv_(iv) { }
        
        std::unique_ptr<UCHAR[]> decrypt(const std::vector<uint8_t>& encodedVec, size_t& outLen) const;
        std::string decryptAsString(const std::vector<uint8_t>& encodedVec, size_t& outLen) const;

        std::vector<uint8_t> encrypt(std::string_view plainText) const;

    private:
        void handleErrors() const;

        std::vector<uint8_t> key_;
        std::vector<uint8_t> iv_;
    };
}
