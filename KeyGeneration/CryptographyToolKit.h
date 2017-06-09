#pragma once
#include <string>
#include "Key.h"
using namespace std;

namespace Cryptography{
	class CryptographyToolkit
	{
	public:
		CryptographyToolkit();
		
		string keygen(int bits); // Generate key according to bits size

	private:
		Key key_gen;
	};

}
