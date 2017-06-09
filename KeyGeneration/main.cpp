#include <iostream>
#include <string>
#include <cstdlib>
#include "CryptographyToolKit.h"
#include "..\cryptopp565\cryptlib.h"
#include "..\cryptopp565\filters.h"
#include "assert.h"
#include "..\cryptopp565\ccm.h"
#include "..\cryptopp565\aes.h"
#include "..\cryptopp565\hex.h"
#include "Key.h"
#include "..\cryptopp565\osrng.h"
using CryptoPP::AutoSeededRandomPool;
using namespace std;
using std::cout;
using std::cerr;
using std::endl;

using std::string;
using std::exit;

using CryptoPP::Exception;

using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

using CryptoPP::AES;

using CryptoPP::CBC_Mode;

void keygen_demo();
void aes_encryptdecrypt();

int main() {
	int choice;

	cout << "Seclct a choice : " << endl;
	keygen_demo();
	cout << "1. AES" << endl;
	cout << "Choice : ";
	cin >> choice;

	if (choice == 1)
	{
		aes_encryptdecrypt();
	}

	system("pause");
	return 0;
}

void keygen_demo() {
	Cryptography::CryptographyToolkit tool;
	cout << "Key Generator Demo..." << endl;
	// Every 8 bits = 1 bytes
	// Note** Key gen only able factor of 4 bytes(32 bits)
	cout << "Generate 4 byte key: " << tool.keygen(32) << endl;  
	cout << "Generate 8 byte key: " << tool.keygen(64) << endl;
	cout << "Generate 12 byte key: " << tool.keygen(128) << endl;
	cout << "Generate 32 byte key: " << tool.keygen(256) << endl;
	cout << "Generate 64 byte key: " << tool.keygen(512) << endl;
}

void aes_encryptdecrypt() {

		AutoSeededRandomPool prng;

		byte key[AES::DEFAULT_KEYLENGTH];
		prng.GenerateBlock(key, sizeof(key));

		byte iv[AES::BLOCKSIZE];
		prng.GenerateBlock(iv, sizeof(iv));

		string plain;
		string cipher, encoded, recovered;

		/*********************************\
		\*********************************/
		cin.ignore();
		cout << "Enter plain text : ";
		getline(cin, plain);

		// Pretty print key
		encoded.clear();
		StringSource(key, sizeof(key), true,
			new HexEncoder(
				new StringSink(encoded)
			) // HexEncoder
		); // StringSource

		cout << "key: " << encoded << endl;
		cout << "key size : " << sizeof(key) << endl;

		// Pretty print iv
		encoded.clear();
		StringSource(iv, sizeof(iv), true,
			new HexEncoder(
				new StringSink(encoded)
			) // HexEncoder
		); // StringSource
		cout << "iv : " << encoded << endl;
		cout << "size of iv :" << sizeof(iv) << endl;

		/*********************************\
		\*********************************/

		try
		{
			cout << "plain text: " << plain << endl;

			CBC_Mode< AES >::Encryption e;
			e.SetKeyWithIV(key, sizeof(key), iv);

			// The StreamTransformationFilter removes
			//  padding as required.
			StringSource s(plain, true,
				new StreamTransformationFilter(e,
					new StringSink(cipher)
				) // StreamTransformationFilter
			); // StringSource

#if 0
			StreamTransformationFilter filter(e);
			filter.Put((const byte*)plain.data(), plain.size());
			filter.MessageEnd();
			const size_t ret = filter.MaxRetrievable();
			cipher.resize(ret);
			filter.Get((byte*)cipher.data(), cipher.size());
#endif
		}
		catch (const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
			exit(1);
		}

		/*********************************\
		\*********************************/

		// Pretty print
		encoded.clear();
		StringSource(cipher, true,
			new HexEncoder(
				new StringSink(encoded)
			) // HexEncoder
		); // StringSource
		cout << "cipher text: " << encoded << endl;

		/*********************************\
		\*********************************/

		try
		{
			CBC_Mode< AES >::Decryption d;
			d.SetKeyWithIV(key, sizeof(key), iv);

			// The StreamTransformationFilter removes
			//  padding as required.
			StringSource s(cipher, true,
				new StreamTransformationFilter(d,
					new StringSink(recovered)
				) // StreamTransformationFilter
			); // StringSource

#if 0
			StreamTransformationFilter filter(d);
			filter.Put((const byte*)cipher.data(), cipher.size());
			filter.MessageEnd();
			const size_t ret = filter.MaxRetrievable();
			recovered.resize(ret);
			filter.Get((byte*)recovered.data(), recovered.size());
#endif

			cout << "recovered text: " << recovered << endl;
		}
		catch (const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
			exit(1);
		}

		/*********************************\
		\*********************************/

}