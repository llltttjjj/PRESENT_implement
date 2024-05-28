#pragma once
#include <cstdint>

class present_bitslicing_ctx {
private:
	constexpr static const uint64_t sBox[16] = { 12,5,6,11,9,0,10,13,3,14,15,8,4,7,1,2 };
	uint8_t* k;
	int size;
	uint64_t roundKeys[32] = { 0 };
	void generateRoundKeys();
	void dataRestructure(const uint64_t* matrix, uint64_t* resMatrix) const;
	void addRoundKey(const uint64_t& key, uint64_t* resMatrix) const;
	inline void logicOperate(const uint64_t* inputPtr, uint64_t* matrix) const;
	struct key80state {
		uint64_t front;
		uint16_t end;
	};
	struct key128state {
		uint64_t front;
		uint64_t end;
	};

public:
	present_bitslicing_ctx();
	present_bitslicing_ctx(const char* key, int keySize);
	present_bitslicing_ctx(const present_bitslicing_ctx& ctx);
	~present_bitslicing_ctx();

	void encrypt_64_blocks(const uint64_t* plain, uint64_t* cypher) const;
	void encrypt_64_blocks(const char plain[64][8], char cypher[64][8]) const;

	void encrypt_64_blocks_MultipleTimes(const uint64_t* plain, uint64_t* cypher, int times) const;
	void encrypt_64_blocks_MultipleTimes(const char plain[64][8], char cypher[64][8], int times) const;

	void encrypt_64_blocks_MultipleTimes_With_Transpose(const char plain[64][8], char cypher[64][8], int times) const;
};

present_bitslicing_ctx::present_bitslicing_ctx() {
	k = new uint8_t[10]{};
	size = 10;
	generateRoundKeys();
}

present_bitslicing_ctx::present_bitslicing_ctx(const char* key, int keySize = 80) {
	if (keySize != 80 && keySize != 128)
		std::cerr << "Invalid key size,80 or 128 is recommended.\n";
	size = keySize / 8;
	k = new uint8_t[size];
	for (int i = 0; i < size; i++)
		k[i] = key[i];
	generateRoundKeys();
}

present_bitslicing_ctx::present_bitslicing_ctx(const present_bitslicing_ctx& ctx) {
	size = ctx.size;
	k = new uint8_t[size];
	for (int i = 0; i < size; i++)
		k[i] = ctx.k[i];
	for (int i = 0; i < 32; i++)
		roundKeys[i] = ctx.roundKeys[i];
}

present_bitslicing_ctx::~present_bitslicing_ctx() {
	delete[] k;
}

void present_bitslicing_ctx::generateRoundKeys() {
	if (size == 10) {
		key80state state;
		state.front = state.end = 0;
		for (int i = 0; i < 8; i++)
			state.front ^= (uint64_t)k[i] << (7 - i) * 8;
		state.end = k[8] * 0x100 + k[9];
		roundKeys[0] = state.front;
		for (uint16_t i = 1; i < 32; i++) {
			static uint64_t tmp;
			static uint64_t least60 = 0x0FFFFFFFFFFFFFFF;   // 2^60 - 1
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

void present_bitslicing_ctx::dataRestructure(const uint64_t* matrix,uint64_t* resMatrix) const {
	for (int i = 0; i < 64; i++) {
		static const uint64_t times = (uint64_t)1;
		const uint64_t row = matrix[i];
		for (int j = 0; j < 64; j++)
			resMatrix[j] ^= (row >> j & times) << i;
	}
}

// Function used for encrypting 64 block with one key
void present_bitslicing_ctx::addRoundKey(const uint64_t& key, uint64_t* resMatrix) const {
	for (int i = 0; i < 64; i++)
		if (key >> i & 1)
			resMatrix[i] = ~resMatrix[i];
}

inline void present_bitslicing_ctx::logicOperate(const uint64_t* inputPtr, uint64_t* outputPtr) const {
	uint64_t tmp[4];   // tmp[0:3] represents for T4, T1, T2, T3
	tmp[1] = inputPtr[1] ^ inputPtr[2];
	tmp[2] = inputPtr[2] & tmp[1];
	tmp[3] = inputPtr[3] ^ tmp[2];
	outputPtr[0] = inputPtr[0] ^ tmp[3];

	tmp[2] = tmp[1] & tmp[3];
	tmp[1] = tmp[1] ^ outputPtr[0];
	tmp[2] ^= inputPtr[2];
	tmp[0] = inputPtr[0] | tmp[2];
	outputPtr[16] = tmp[1] ^ tmp[0];

	tmp[0] = ~inputPtr[0];
	tmp[2] ^= tmp[0];
	outputPtr[48] = outputPtr[16] ^ tmp[2];

	tmp[2] |= tmp[1];
	outputPtr[32] = tmp[2] ^ tmp[3];
}

void present_bitslicing_ctx::encrypt_64_blocks(const uint64_t* plain, uint64_t* cypher) const {
	uint64_t stateMatrix[64]{ 0 }, tmpMatrix[64]{ 0 };
	dataRestructure(plain, stateMatrix);
	for (int i = 0; i < 31; i++) {
		addRoundKey(roundKeys[i], stateMatrix);
		for (int j = 0; j < 16; j++)
			logicOperate(&stateMatrix[j << 2], &tmpMatrix[j]);
		for (int j = 0; j < 64; j++)
			stateMatrix[j] = tmpMatrix[j];
	}
	addRoundKey(roundKeys[31], stateMatrix);
	for (int i = 0; i < 64; i++)
		cypher[i] = 0;
	dataRestructure(stateMatrix, cypher);
}

void present_bitslicing_ctx::encrypt_64_blocks(const char plain[64][8], char cypher[64][8]) const {
	uint64_t pl[64]{ 0 }, cy[64];
	for (int i = 0; i < 64; i++)
		for (int j = 0; j < 8; j++)
			pl[i] ^= (uint64_t)(unsigned char)plain[i][j] << ((7 - j) << 3);
	encrypt_64_blocks(pl, cy);
	for (int i = 0; i < 64; i++) {
		for (int j = 0; j < 8; j++)
			cypher[i][j] = cy[i] >> ((7 - j) << 3) & 0xFF;
	}
}

void present_bitslicing_ctx::encrypt_64_blocks_MultipleTimes(const uint64_t* plain, uint64_t* cypher, int times) const {
	uint64_t stateMatrix[64]{ 0 }, tmpMatrix[64]{ 0 };
	dataRestructure(plain, stateMatrix);
	for (int count = 0; count < times; count++) {
		for (int i = 0; i < 31; i++) {
			addRoundKey(roundKeys[i], stateMatrix);
			for (int j = 0; j < 16; j++)
				logicOperate(&stateMatrix[j << 2], &tmpMatrix[j]);
			for (int j = 0; j < 64; j++)
				stateMatrix[j] = tmpMatrix[j];
		}
		addRoundKey(roundKeys[31], stateMatrix);
	}
	for (int i = 0; i < 64; i++)
		cypher[i] = 0;
	dataRestructure(stateMatrix, cypher);
}
void present_bitslicing_ctx::encrypt_64_blocks_MultipleTimes(const char plain[64][8], char cypher[64][8], int times) const {
	uint64_t pl[64]{ 0 }, cy[64];
	for (int i = 0; i < 64; i++)
		for (int j = 0; j < 8; j++)
			pl[i] ^= (uint64_t)(unsigned char)plain[i][j] << ((7 - j) << 3);
	encrypt_64_blocks_MultipleTimes(pl, cy, times);
	for (int i = 0; i < 64; i++) {
		for (int j = 0; j < 8; j++)
			cypher[i][j] = cy[i] >> ((7 - j) << 3) & 0xFF;
	}
}

void present_bitslicing_ctx::encrypt_64_blocks_MultipleTimes_With_Transpose(const char plain[64][8], char cypher[64][8], int times) const {
	uint64_t state[64]{ 0 };
	for (int i = 0; i < 64; i++)
		for (int j = 0; j < 8; j++)
			state[i] ^= (uint64_t)(unsigned char)plain[i][j] << ((7 - j) << 3);
	for (int i = 0; i < times; i++)
		encrypt_64_blocks(state, state);
	for (int i = 0; i < 64; i++) {
		for (int j = 0; j < 8; j++)
			cypher[i][j] = state[i] >> ((7 - j) << 3) & 0xFF;
	}
}