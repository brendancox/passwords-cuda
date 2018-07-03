#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

extern "C" {
    #include "sha.h"
}

void HexToBytes(const std::string& hex, unsigned char * &newsalt) {
    for (unsigned int i = 0; i < hex.length(); i += 2) {
      std::string byteString = hex.substr(i, 2);
      char byte = (char) strtol(byteString.c_str(), NULL, 16);
      newsalt[i/2] = byte;
    }
}

// Compile with: nvcc exp.cu sha384-512.c sha224-256.c sha1.c usha.c hmac.c -o build/exp

void pbkdf2(std::string password, std::string salt, uint8_t digest[USHAMaxHashSize]) {

    // Hashing function will be sha256. hlen will therefore be 32, same as keyLen.
    // Desired key length will be 32.
    // iterations will be 100000.
    int rounds = 100000;
    unsigned char * pw = (unsigned char *)password.c_str();
    int pwsize = password.size();

    uint8_t dk[USHAMaxHashSize];

    unsigned char * newsalt = (unsigned char *)malloc(16);
    HexToBytes(salt, newsalt);
    newsalt[16] = (1 >> 24) & 0xff;
    newsalt[17] = (1 >> 16) & 0xff;
    newsalt[18] = (1 >> 8) & 0xff;
    newsalt[19] = (1 >> 0) & 0xff;

    hmac(
        SHA256,
        newsalt,
        20,
        pw,
        pwsize,
        digest
    );

    for (int a = 0; a < 32; a++) {
        dk[a] = digest[a];
    }

    uint8_t newdigest[32];
    uint8_t runningkey[32];
    memcpy(runningkey, dk, 32);
    for (int i = 2; i <= rounds; i++) {
        hmac(
            SHA256,
            runningkey,
            32,
            pw,
            pwsize,
            newdigest
        );

        for (int j = 0; j < 32; j++) {
            dk[j] = dk[j] ^ newdigest[j];
            runningkey[j] = newdigest[j];
        }
    }

    for (int b = 0; b < 32; b++) {
        digest[b] = dk[b];
    }
}



int main(void)
{
    std::cout << "Running" << std::endl;

    std::string testpw = "glassy ubiquity absence";
    std::string testsalt = "2db485972861e63479528bf382d1bc04";
    std::string testhash = "3c453512d47b37352bf2c5c1408ea4d9f46c48878782843a685c0c7e54232ba0";

    unsigned char * newsalt = (unsigned char *)malloc(16);
    HexToBytes(testsalt, newsalt);

    uint8_t prk[USHAMaxHashSize];

    hmac(
        SHA256,
        newsalt,
        16,
        (unsigned char *)testpw.c_str(),
        testpw.size(),
        prk
    );

    //char * hex_str = "";
    //hex_str = itoa(*prk, hex_str, 16);
    //sprintf(hex_str.c_str(),"%x", *prk);
    
    for (int i = 0; i < SHA256HashSize; i++) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(prk[i]);
    }
    std::cout << std::endl;

    std::cout << "hmac Done" << std::endl;

    uint8_t pdprk[USHAMaxHashSize];

    pbkdf2(testpw, testsalt, pdprk);

    for (int i = 0; i < SHA256HashSize; i++) {
        //printf("%x", prk[i]);
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(pdprk[i]);
    }
    std::cout << std::endl;

    std::cout << "pbkdf2 Done" << std::endl;

    return 0;
}

