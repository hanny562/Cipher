#include "Key.h"
#include <random>  
#include <chrono>
#include <math.h>
#include <iostream>
#include <string>

using namespace std;

Cryptography::Key::Key() {
	   
	gen = mt19937(time(0)) ; // Declare gen as mersenne twester random generator 
}

string Cryptography::Key::keygen(int bits) {


	string key;
	// For every loop, generate 32 bit/ 4 bytes key.
	// Round of loop according to the bits/bytes size require for key
	for (int i = 0; i < bits; i = i + 32) {
		uint32_t random32 = gen(); // store random 32 bits value 
		char hex[33];
		_itoa_s(random32, hex, 16);// conver 32 bit random value to 4 bytes hex value
		string hexa = hex;// store hex array into string
		key = key + hexa;// combine every 4 bytes hex to form a key
	}
	return key;
}
string Cryptography::Key::keygen_new(int bits) {
	random_device rd;// non-deterministic generator
	gen = mt19937{ rd() }; // to seed mersenne twister. 
	return keygen(bits);
}