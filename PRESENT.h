#pragma once
#include <iostream>
#include <cstdint>

class PRESENT_ctx {
private:

	constexpr static const uint64_t sBox[16] = { 12,5,6,11,9,0,10,13,3,14,15,8,4,7,1,2 };
	constexpr static const short p[64] =
	{ 0,16,32,48,1,17,33,49,2,18,34,50,3,19,35,51,
	4,20,36,52,5,21,37,53,6,22,38,54,7,23,39,55,
	8,24,40,56,9,25,41,57,10,26,42,58,11,27,43,59,
	12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63 };

	constexpr static const uint64_t sBox_inv[16] = { 5,14,15,8,12,1,2,13,11,4,6,3,0,7,9,10 };
	constexpr static const short p_inv[64] =
	{ 0,4,8,12,16,20,24,28,32,36,40,44,48,52,56,60,
	1,5,9,13,17,21,25,29,33,37,41,45,49,53,57,61,
	2,6,10,14,18,22,26,30,34,38,42,46,50,54,58,62,
	3,7,11,15,19,23,27,31,35,39,43,47,51,55,59,63 };

	uint8_t* k;
	int size;
	uint64_t roundKeys[32] = { 0 };
	void generateRoundKeys();

	struct key80state {
		uint64_t front;
		uint16_t end;
	};
	struct key128state {
		uint64_t front;
		uint64_t end;
	};


	inline void addRoundKey(uint64_t& state, const uint64_t& K) const;

	inline void sBoxLayer(uint64_t& state) const;

	inline void pLayer(uint64_t& state) const;

	inline void sBoxLayer_inv(uint64_t& state) const;

	inline void pLayer_inv(uint64_t& state) const;

public:

	PRESENT_ctx();
	PRESENT_ctx(const char* key, int keySize);
	PRESENT_ctx(const PRESENT_ctx& ctx);
	~PRESENT_ctx();

	void encrypt_block(const uint64_t& plain, uint64_t& cypher) const;
	void encrypt_block_MultipleTimes(const uint64_t& plain, uint64_t& cypher, int times) const;
	void decrypt_block(const uint64_t& cypher, uint64_t& decypher) const;

	void encrypt_block(const char* plain, char* cypher) const;
	void encrypt_block_MultipleTimes(const char* plain, char* cypher, int times) const;
	void decrypt_block(const char* cypher, char* decypher) const;

	void encrypt_cbc(const char* plaintext, const char* IV, char* cyphertext,const int plen);
};

// Take all 0s key for default
PRESENT_ctx::PRESENT_ctx() {
	k = new uint8_t[10]{};
	size = 10;
	generateRoundKeys();
}

PRESENT_ctx::PRESENT_ctx(const char* key, int keySize = 80) {
	if (keySize != 80 && keySize != 128)
		std::cerr << "Invalid key size,80 or 128 is recommended.\n";
	size = keySize / 8;
	k = new uint8_t[size];
	for (int i = 0; i < size; i++)
		k[i] = key[i];
	generateRoundKeys();
}

PRESENT_ctx::PRESENT_ctx(const PRESENT_ctx& ctx) {
	size = ctx.size;
	k = new uint8_t[size];
	for (int i = 0; i < size; i++)
		k[i] = ctx.k[i];
	for (int i = 0; i < 32; i++)
		roundKeys[i] = ctx.roundKeys[i];
}

PRESENT_ctx::~PRESENT_ctx() { }

// Encrypt function used for one block
void PRESENT_ctx::encrypt_block(const uint64_t& plain, uint64_t& cypher) const{
	uint64_t state = plain;
	for (int i = 0; i < 31; i++) {
		addRoundKey(state,roundKeys[i]);
		sBoxLayer(state);
		pLayer(state);
	}
	addRoundKey(state, roundKeys[31]);
	cypher = state;
}

void PRESENT_ctx::encrypt_block(const char* plain, char* cypher) const{
	uint64_t pl = 0, cy;
	for (int i = 0; i < 8; i++)
		pl ^= (uint64_t)(unsigned char)plain[i] << ((7 - i) << 3);
	encrypt_block(pl, cy);
	for (int i = 0; i < 8; i++)
		cypher[i] = cy >> ((7 - i) << 3) & 0xFF;
}

void PRESENT_ctx::encrypt_block_MultipleTimes(const uint64_t& plain, uint64_t& cypher, int times) const {
	uint64_t state = plain;
	for (int count = 0; count < times; count++) {
		for (int i = 0; i < 31; i++) {
			addRoundKey(state, roundKeys[i]);
			sBoxLayer(state);
			pLayer(state);
		}
		addRoundKey(state, roundKeys[31]);
	}
	cypher = state;
}

void PRESENT_ctx::encrypt_block_MultipleTimes(const char* plain, char* cypher, int times) const {
	uint64_t pl = 0, cy;
	for (int i = 0; i < 8; i++)
		pl ^= (uint64_t)(unsigned char)plain[i] << ((7 - i) << 3);
	encrypt_block_MultipleTimes(pl, cy, times);
	for (int i = 0; i < 8; i++)
		cypher[i] = cy >> ((7 - i) << 3) & 0xFF;
}

// Decrypt function used for one block
void PRESENT_ctx::decrypt_block(const uint64_t& cypher, uint64_t& decypher) const {
	uint64_t state = cypher;
	for (int i = 31; i > 0; i--) {
		addRoundKey(state, roundKeys[i]);
		pLayer_inv(state);
		sBoxLayer_inv(state);
	}
	addRoundKey(state, roundKeys[0]);
	decypher = state;
}

void PRESENT_ctx::decrypt_block(const char* cypher, char* decypher) const {
	uint64_t cy = 0, dec;
	for (int i = 0; i < 8; i++)
		cy ^= (uint64_t)(unsigned char)cypher[i] << ((7 - i) << 3);
	decrypt_block(cy, dec);
	for (int i = 0; i < 8; i++)
		decypher[i] = dec >> ((7 - i) << 3) & 0xFF;
}

void PRESENT_ctx::encrypt_cbc(const char* plaintext, const char* IV, char* cyphertext, const int len) {
	char state[8];
	char* cypherPtr;
	for (int i = 0; i < 8; i++)
		state[i] = IV[i];
	for (uint64_t i = 0; i < len / 8; i++) {
		for (int i = 0; i < 8; i++)
			state[i] ^= plaintext[i];
		cypherPtr = &cyphertext[i << 3];
		encrypt_block(state, cypherPtr);
	}
}

// Generate 32 round keys
inline void PRESENT_ctx::generateRoundKeys() {
	if (size == 10) {
		key80state state;
		state.front = state.end = 0;
		for (int i = 0; i < 8; i++)
			state.front ^= (uint64_t)k[i] << (7 - i) * 8;
		state.end = k[8] << 8 ^ k[9];
		roundKeys[0] = state.front;
		for (uint16_t i = 1; i < 32; i++) {
			static uint64_t tmp;
			static const uint64_t least60 = 0x0FFFFFFFFFFFFFFF;   // 2^60 - 1
			tmp = state.front >> 19 ^ uint64_t(state.end) << 45 ^ state.front << 61;
			state.end = state.front >> 3 & 0xFFFF;
			state.front = (tmp & least60) ^ sBox[tmp >> 60] << 60;
			state.front ^= i >> 1;
			state.end ^= i << 15;
			roundKeys[i] = state.front;
		}
	}
	if (size == 16) {
		key128state state;
		state.front = state.end = 0;
		for (int i = 0; i < 8; i++) {
			state.front ^= (uint64_t)k[i] << (7 - i) * 8;
			state.end ^= (uint64_t)k[i + 8] << (7 - i) * 8;
		}
		roundKeys[0] = state.front;
		for (uint64_t i = 1; i < 32; i++) {
			static uint64_t tmp;
			static uint64_t least56 = 0x00FFFFFFFFFFFFFF;   // 2^56 - 1
			tmp = state.front << 61 ^ state.end >> 3;
			state.end = state.front >> 3 ^ state.end << 61;
			state.front = (tmp & least56) ^ sBox[tmp >> 60] << 60 ^ sBox[tmp >> 56 & 0xF] << 56;
			state.front ^= i >> 2;
			state.end ^= i << 62;
			roundKeys[i] = state.front;
		}
	}
}

inline void PRESENT_ctx::addRoundKey(uint64_t& state, const uint64_t& K)  const { state ^= K; }

inline void PRESENT_ctx::sBoxLayer(uint64_t& state) const {
	uint64_t tmp = 0;
	for (uint8_t i = 0; i < 16; i++)
		tmp ^= sBox[(state >> (i << 2)) & 0xF] << (i << 2);
	state = tmp;
}

inline void PRESENT_ctx::pLayer(uint64_t& state) const {
	uint64_t tmp = 0;
	static const uint64_t start = 1;
	for (int i = 0; i < 64; i++)
		if (state >> i & 1)
			tmp ^= start << p[i];
	state = tmp;
}

inline void PRESENT_ctx::sBoxLayer_inv(uint64_t& state) const {
	uint64_t tmp = 0;
	for (uint8_t i = 0; i < 16; i++)
		tmp ^= sBox_inv[(state >> (i << 2)) & 0xF] << (i << 2);
	state = tmp;
}

inline void PRESENT_ctx::pLayer_inv(uint64_t& state) const {
	uint64_t tmp = 0;
	const uint64_t start = 1;
	for (int i = 0; i < 64; i++)
		if (state >> i & 1)
			tmp ^= start << p_inv[i];
	state = tmp;
}
