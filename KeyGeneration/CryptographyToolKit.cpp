#include <iostream>
#include <string>
#include "CryptographyToolKit.h"
using namespace std;

Cryptography::CryptographyToolkit::CryptographyToolkit() : key_gen(Key()) {}

string Cryptography::CryptographyToolkit::keygen(int bits) {
	return key_gen.keygen(bits);
}

