// Copyright (c) 2013-2014 The OpenSSL developers
// Copyright (c) 2013-2014 The Slimcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string.h>        //for strlen

#include "dcrypt_sha256.h"

char * byte_to_hex =
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f"
        "505152535455565758595a5b5c5d5e5f"
        "606162636465666768696a6b6c6d6e6f"
        "707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

inline void digest_to_string(u8int *hash_digest, u8int *str)
{
  memcpy(str+0 ,byte_to_hex + hash_digest[0]*2,2);
  memcpy(str+2 ,byte_to_hex + hash_digest[1]*2,2);
  memcpy(str+4 ,byte_to_hex + hash_digest[2]*2,2);
  memcpy(str+6 ,byte_to_hex + hash_digest[3]*2,2);
  memcpy(str+8 ,byte_to_hex + hash_digest[4]*2,2);
  memcpy(str+10,byte_to_hex + hash_digest[5]*2,2);
  memcpy(str+12,byte_to_hex + hash_digest[6]*2,2);
  memcpy(str+14,byte_to_hex + hash_digest[7]*2,2);
  memcpy(str+16,byte_to_hex + hash_digest[8]*2,2);
  memcpy(str+18,byte_to_hex + hash_digest[9]*2,2);
  memcpy(str+20,byte_to_hex + hash_digest[10]*2,2);
  memcpy(str+22,byte_to_hex + hash_digest[11]*2,2);
  memcpy(str+24,byte_to_hex + hash_digest[12]*2,2);
  memcpy(str+26,byte_to_hex + hash_digest[13]*2,2);
  memcpy(str+28,byte_to_hex + hash_digest[14]*2,2);
  memcpy(str+30,byte_to_hex + hash_digest[15]*2,2);
  memcpy(str+32,byte_to_hex + hash_digest[16]*2,2);
  memcpy(str+34,byte_to_hex + hash_digest[17]*2,2);
  memcpy(str+36,byte_to_hex + hash_digest[18]*2,2);
  memcpy(str+38,byte_to_hex + hash_digest[19]*2,2);
  memcpy(str+40,byte_to_hex + hash_digest[20]*2,2);
  memcpy(str+42,byte_to_hex + hash_digest[21]*2,2);
  memcpy(str+44,byte_to_hex + hash_digest[22]*2,2);
  memcpy(str+46,byte_to_hex + hash_digest[23]*2,2);
  memcpy(str+48,byte_to_hex + hash_digest[24]*2,2);
  memcpy(str+50,byte_to_hex + hash_digest[25]*2,2);
  memcpy(str+52,byte_to_hex + hash_digest[26]*2,2);
  memcpy(str+54,byte_to_hex + hash_digest[27]*2,2);
  memcpy(str+56,byte_to_hex + hash_digest[28]*2,2);
  memcpy(str+58,byte_to_hex + hash_digest[29]*2,2);
  memcpy(str+60,byte_to_hex + hash_digest[30]*2,2);
  memcpy(str+62,byte_to_hex + hash_digest[31]*2,2);

  str[SHA256_LEN] = 0;
  return;
}

//static void digest_to_string(u8int *hash_digest, u8int *string)
void old_digest_to_string(u8int *hash_digest, u8int *string)
{
  register u8int tmp_val;

  uint8_t i = 0, *ps;
  for(; i < SHA256_DIGEST_LENGTH; i++)
  {
	ps = string + i * 2;
    tmp_val = *(hash_digest + i) >> 4;
    if(tmp_val < 10)
      *ps = tmp_val + 48;
    else
      *ps = tmp_val + 87;
    tmp_val = *(hash_digest + i) & 0xf;
    if(tmp_val < 10)
      *(ps + 1) = tmp_val + 48;
    else
      *(ps + 1) = tmp_val + 87;

  }

  //add the termination \000 to the string
  *(string + SHA256_LEN) = 0;
  
  return;
}

void sha256_to_str(const u8int *data, size_t data_sz, u8int *outputBuffer, u8int *hash_digest)
{
  SHA256_CTX sha256;
  static u8int __digest__[SHA256_DIGEST_LENGTH];

  if(hash_digest == NULL)
    hash_digest = __digest__;

  SHA256_Init(&sha256);
  SHA256_Update(&sha256, data, data_sz);
  SHA256_Final(hash_digest, &sha256);

  //convert the digest to a string
  digest_to_string(hash_digest, outputBuffer);

  //sucess!
  return;
}

//optional arg: hash_digest
// same code from openssl lib, just a bit more specialized
u32int *sha256(const u8int *data, size_t data_sz, u32int *hash_digest)
{
  SHA256_CTX hash;

  SHA256_Init(&hash);
  SHA256_Update(&hash, data, data_sz);
  SHA256_Final((u8int*)hash_digest, &hash);
  //~ OPENSSL_cleanse(&hash, sizeof(hash));

  return hash_digest;
}

void sha256_salt_to_str(const u8int *data, size_t data_sz, u8int *salt, size_t salt_sz, 
                        u8int *outputBuffer, u8int *hash_digest)
{
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, data, data_sz);
  SHA256_Update(&sha256, salt, salt_sz);
  SHA256_Final(hash_digest, &sha256);

  //convert the digest to a string
  digest_to_string(hash_digest, outputBuffer);    

  //sucess!
  return;
}
