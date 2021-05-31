#include "table_opprf.h"
#include <openssl/sha.h>
#include <random>
#include<cstring>

/*
 * Hash an element to position
 */
std::uint64_t hashToPosition(std::uint64_t element, osuCrypto::block nonce) {
	SHA_CTX ctx;
	unsigned char hash[SHA_DIGEST_LENGTH];

	unsigned char* message=(unsigned char*)malloc(sizeof(std::uint64_t)+sizeof(osuCrypto::block));
	memcpy(message, &element,sizeof(std::uint64_t));
	memcpy(message+sizeof(std::uint64_t), &nonce, sizeof(osuCrypto::block));

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, message, sizeof(std::uint64_t)+sizeof(osuCrypto::block));
	SHA1_Final(hash, &ctx);

	std::uint64_t result = 0;
	std::copy(hash, hash + sizeof(result), reinterpret_cast<unsigned char*>(&result));

	return result;
}
