#pragma once
// This header is used for generating lookup tables 
#include <iostream>
#include <cstdint>
#include "PRESENT.h"
using namespace std;

void genTables_4bitInput() {
	const uint64_t sBox[16] = { 12,5,6,11,9,0,10,13,3,14,15,8,4,7,1,2 };
	const short pBox[64] =
	{ 0,16,32,48,1,17,33,49,2,18,34,50,3,19,35,51,
	4,20,36,52,5,21,37,53,6,22,38,54,7,23,39,55,
	8,24,40,56,9,25,41,57,10,26,42,58,11,27,43,59,
	12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63 };

	cout << "static const uint64_t lookup_4bit[16][16] = \n{";
	uint64_t state, tmp;
	const uint64_t start = 1;
	for (int i = 0; i < 16; i++) {
		cout << "{";
		for (uint64_t j = 0; j < 16; j++) {
			int num = (15 - i) << 2;
			tmp = sBox[j] << num;
			state = tmp;
			tmp = 0;
			for (int k = 0; k < 64; k++)
				if (state >> k & 1)
					tmp ^= start << pBox[k];
			cout << "0x" << tmp << ", ";
		}
		if (i != 15) cout << "\b\b},\n";
		else cout << "\b\b}";
	}
	cout << "};\n";
}

void genTables_8bitInput() {
	const uint64_t sBox[16] = { 12,5,6,11,9,0,10,13,3,14,15,8,4,7,1,2 };
	const short pBox[64] =
	{ 0,16,32,48,1,17,33,49,2,18,34,50,3,19,35,51,
	4,20,36,52,5,21,37,53,6,22,38,54,7,23,39,55,
	8,24,40,56,9,25,41,57,10,26,42,58,11,27,43,59,
	12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63 };

	cout << "static const uint64_t lookup_8bit[8][256] = \n{";
	uint64_t state, tmp;
	const uint64_t start = 1;
	for (int i = 0; i < 8; i++) {
		cout << "{";
		for (uint64_t j = 0; j < 256; j++) {
			int num = (7 - i) << 3;
			tmp = (sBox[j & 0xF] << num) ^ (sBox[j >> 4] << num << 4);
			state = tmp;
			tmp = 0;
			for (int k = 0; k < 64; k++)
				if (state >> k & 1)
					tmp ^= start << pBox[k];
			cout << "0x" << tmp << ", ";
		}
		if (i != 7) cout << "\b\b},\n";
		else cout << "\b\b}";
	}
	cout << "};\n";
}