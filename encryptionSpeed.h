#pragma once

#include "PRESENT.h"
#include "present_lookup.h"
#include "present_bitslicing.h"
#include <ctime>
//#include <Windows.h>
#include <intrin.h>

using namespace std;

void performanceTest() {
	const uint64_t runTimes = 10000000;   // The tesing time
	const char ch[10] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	//const char ch[10] = { 0x52,(char)0xDF,0x39,(char)0x95,(char)0xB6,(char)0xE9,(char)0xE8,(char)0xBD,(char)0xDB,0x2C };   // A random key
	PRESENT_ctx originCTX(ch);
	present_lookup_ctx lookupCTX(ch);
	present_bitslicing_ctx bitSlicingCTX(ch);
	char state[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	char stateForBitSlicing[64][8];

	uint64_t clkstart, clkend;
	clock_t start;

	//// Testing the original implement
	//cout << "Testing the original implement " << dec << runTimes << " times.\n";
	//start = clock();
	//clkstart = __rdtsc();
	//originCTX.encrypt_block_MultipleTimes(state, state, runTimes);
	//clkend = __rdtsc();
	//cout << "Performance: " << (double)(clkend - clkstart) / (8 * runTimes) << " CPB\n";
	//cout << "The output is: ";
	//for (int i = 0; i < 8; i++)
	//	printf("%02X", (unsigned char)state[i]);
	//cout << "\nCosts " << clock() - start << " ms.\n\n";

	// Reset state
	for (int i = 0; i < 8; i++) state[i] = 0;

	// Testing the implement with new lookup table
	cout << "Testing the implement with new lookup table " << runTimes << " times.\n";
	start = clock();
	clkstart = __rdtsc();
	lookupCTX.encrypt_block_MultipleTimes(state, state, runTimes);
	clkend = __rdtsc();
	cout << "Performance: " << (double)(clkend - clkstart) / (8 * runTimes) << " CPB\n";
	cout << "The output is: ";
	for (int i = 0; i < 8; i++)
		printf("%02X", (unsigned char)state[i]);
	cout << "\nCosts " << clock() - start << " ms.\n\n";

	// Set state for bit-slicing encryption
	for (int i = 0; i < 64; i++)
		for (int j = 0; j < 8; j++)
			stateForBitSlicing[i][j] = (char)i;

	// Testing the implement with new bit-slicing
	cout << "Testing the implement with bit-slicing to encrypt 64 different plaintext " << runTimes << " times.\n";
	start = clock();
	clkstart = __rdtsc();
	// The following method doesn't transpose the matrix, which makes it much faster. However, if it requires to keep tracks on intermediates, transposing is nessesary.
	//bitSlicingCTX.encrypt_64_blocks_MultipleTimes(stateForBitSlicing, stateForBitSlicing, runTimes);
	
	// The simple method that transposes every time
	bitSlicingCTX.encrypt_64_blocks_MultipleTimes_With_Transpose(stateForBitSlicing, stateForBitSlicing, runTimes);

	clkend = __rdtsc();
	cout << "Performance: " << (double)(clkend - clkstart) / (64 * 8 * runTimes) << " CPB\n";
	cout << "Costs " << clock() - start << " ms.\n";
	cout << "The output is: \n";
	for (int content = 0; content < 64; content++) {
		printf("0x%02X: ", content);
		for (int i = 0; i < 8; i++)
			printf("%02X", (unsigned char)stateForBitSlicing[content][i]);
		if (content % 8 == 7)
			cout << "\n";
		else
			cout << "|";
	}
	cout << endl;
	
	// Set state for lookup encryption
	for (int i = 0; i < 64; i++)
		for (int j = 0; j < 8; j++)
			stateForBitSlicing[i][j] = (char)i;

	// Doing the same job using present_lookup
	cout << "Testing the implement with new lookup table to encrypt 64 different plaintext " << runTimes << " times.\n";
	start = clock();
	clkstart = __rdtsc();
	for (int content = 0; content < 64; content++) {
		lookupCTX.encrypt_block_MultipleTimes(stateForBitSlicing[content], stateForBitSlicing[content], runTimes);
	}
	clkend = __rdtsc();
	cout << "Performance: " << (double)(clkend - clkstart) / (64 * 8 * runTimes) << " CPB\n";
	cout << "Costs " << clock() - start << " ms.\n";
	cout << "The output is: \n";
	for (int content = 0; content < 64; content++) {
		printf("0x%02X: ", content);
		for (int i = 0; i < 8; i++)
			printf("%02X", (unsigned char)stateForBitSlicing[content][i]);
		if (content % 8 == 7)
			cout << "\n";
		else
			cout << "|";
	}
	cout << endl;
}