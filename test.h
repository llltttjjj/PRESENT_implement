#pragma once
// This header is used for testing
#include "PRESENT.h"
#include <iostream>
#include "present_lookup.h"
#include "present_bitslicing.h"

using namespace std;

char ch[64][10] =
{ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
{ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1 } };

void test_origin() {
	cout << "Testing the validity of original implement:\n";
	char cypher[8], decypher[8];
	cout << "plain            key                  "
		<< "cipher           decypher\n";
	for (int i = 0; i < 4; i++) {
		PRESENT_ctx pctx(ch[i % 2]);
		pctx.encrypt_block(ch[i / 2], cypher);
		pctx.decrypt_block(cypher, decypher);
		for (int j = 0; j < 8; j++)
			printf("%02X", (unsigned char)ch[i / 2][j]);   // the plaintext
		cout << " ";
		for (int j = 0; j < 10; j++)
			printf("%02X", (unsigned char)ch[i % 2][j]);   // the key
		cout << " ";
		for (int j = 0; j < 8; j++)
			printf("%02X", (unsigned char)cypher[j]);   // the cyphertext
		cout << " ";
		for (int j = 0; j < 8; j++)
			printf("%02X", (unsigned char)decypher[j]);   // decypher
		cout << endl;
	}
	PRESENT_ctx pctx("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 128);
	pctx.encrypt_block(ch[0], cypher);
	cout <<"16 Bytes Key Encryption : ";
	for (int j = 0; j < 8; j++)
		printf("%02X", (unsigned char)cypher[j]);
	cout << endl;
}

void test_lookup() {
	cout << "Testing the validity of the lookup table implement:\n";
	char cypher[8];
	cout << "plain            key                  "
		<< "cipher\n";
	for (int i = 0; i < 4; i++) {
		present_lookup_ctx plctx(ch[i % 2]);
		plctx.encrypt_block(ch[i / 2], cypher);
		for (int j = 0; j < 8; j++)
			printf("%02X", (unsigned char)ch[i / 2][j]);   // the plaintext
		cout << " ";
		for (int j = 0; j < 10; j++)
			printf("%02X", (unsigned char)ch[i % 2][j]);   // the key
		cout << " ";
		for (int j = 0; j < 8; j++)
			printf("%02X", (unsigned char)cypher[j]);   // the cyphertext
		cout << endl;
	}
	present_lookup_ctx plctx("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 128);
	plctx.encrypt_block(ch[0], cypher);
	cout << "16 Bytes Key Encryption : ";
	for (int j = 0; j < 8; j++)
		printf("%02X", (unsigned char)cypher[j]);
	cout << endl;
}

void test_bitslicing() {
	cout << "Testing the validity of the bit-slicing implement:\n";
	cout << "plain            key                  "
		<< "cipher\n";

	const char plain[64][8] = 
		{ { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
		{ -1,-1,-1,-1,-1,-1,-1,-1 } };   // -1 == 0xFF   LLVM compiler doesn't allow using 0xFF to initiate char variables
	char cypher[64][8];
	
	for (int i = 0; i < 2; i++) {
		present_bitslicing_ctx pbctx(ch[i % 2]);
		pbctx.encrypt_64_blocks(plain, cypher);
		for (int j = 0; j < 8; j++)
			printf("%02X", (unsigned char)plain[0][j]);   // the plaintext
		cout << " ";
		for (int j = 0; j < 10; j++)
			printf("%02X", (unsigned char)ch[i % 2][j]);   // the key
		cout << " ";
		for (int j = 0; j < 8; j++)
			printf("%02X", (unsigned char)cypher[0][j]);   // the cyphertext
		cout << endl;
		for (int j = 0; j < 8; j++)
			printf("%02X", (unsigned char)plain[1][j]);   // the plaintext
		cout << " ";
		for (int j = 0; j < 10; j++)
			printf("%02X", (unsigned char)ch[i % 2][j]);   // the key
		cout << " ";
		for (int j = 0; j < 8; j++)
			printf("%02X", (unsigned char)cypher[1][j]);   // the cyphertext
		cout << endl;
	}
}
