#pragma once

#include <string>
#include <random>

using namespace std;
namespace Cryptography {
	class Key
	{
	public:
		Key();
		string keygen(int bits);// Generate hex key according to bits size
		string keygen_new(int bits); // new seed for every new key genetared

	private:
		mt19937 gen;
	};
}




