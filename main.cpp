#include <iostream>
#include <iomanip>
#include "test.h"
#include "encryptionSpeed.h"
#include "genTable.h"

using namespace std;

int main() {

	/*test_origin();
	cout << "\n----------------------------\n";
	test_lookup();
	cout << "\n----------------------------\n";
	test_bitslicing();
	cout << "\n----------------------------\n";*/
	performanceTest();

	/*cout << setiosflags(ios::uppercase) << hex;
	genTables_4bitInput();
	genTables_8bitInput();*/

	return 0;
}
// Use LLVM to compile in /O2 optimization options, which is a little faster than MSVC.