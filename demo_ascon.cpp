#include <iostream>
#include "ascon.h"

using namespace std;
using namespace ASCON;

Ascon ascon;

void show(const char *str, const ascon_data& d) {
	std::cout << str << ":\t\t0x";
	for (auto& dat : d) {
		if ((int)dat < 16) {
			std::cout << '0';
		}
		std::cout << hex << (int)dat;
	}
	std::cout << " (" << dec << d.size() << " bytes) " << endl;
}
void show(const char* str, const ascon128bits& d) {
	ascon_data data; data.resize(16);
	for (int i = 0; i < 8; ++i) {
		data[i] = (ascon8bits)(d[0] >> (64 - 8 * (i + 1)));		
		data[i + 8] = (ascon8bits)(d[1] >> (64 - 8 * (i + 1)));
	}
	show(str, data);
}
void show(const char* str, const ascon256bits& d) {
	ascon_data data; data.resize(32);
	for (int i = 0; i < 8; ++i) {
		data[i] = (ascon8bits)(d[0] >> (64 - 8 * (i + 1)));
		data[i + 8] = (ascon8bits)(d[1] >> (64 - 8 * (i + 1)));
		data[i + 16] = (ascon8bits)(d[2] >> (64 - 8 * (i + 1)));
		data[i + 24] = (ascon8bits)(d[3] >> (64 - 8 * (i + 1)));
	}
	show(str, data);
}

void test_ende() {
	std::cout << "========加密解密测试==========" << endl;
	ascon128bits T;
	ascon128bits K = { (ascon64bits)0, (ascon64bits)0 };
	ascon128bits N = { (ascon64bits)0, (ascon64bits)0 };
	ascon_data text = { 0x61, 0x73, 0x63, 0x6f, 0x6e, 0x61, 0x73, 0x63 };  // "asconasc"
	ascon_data associatedata = {};// { 0x41, 0x53, 0x43, 0x4f, 0x4e, 0x41, 0x53, 0x43 };  // "ASCONASC"
	const ascon_data& ciphertext = ascon.Encryption(text, associatedata, K, N, T);
	const ascon_data& plaintext = ascon.Decryption(ciphertext, associatedata, K, N, T);

	show("key", K);
	show("nonce", N);
	show("plaintext", text);
	show("ass.data", associatedata);
	show("ciphertext", ciphertext);
	show("tag", T);
	show("received", plaintext);
}

void test_hash() {
	std::cout << "==============哈希测试=================" << endl;
	ascon_data message = {};// { 0x61, 0x73, 0x63, 0x6f, 0x6e, 0x61, 0x73, 0x63 };  // "asconasc"
	const ascon256bits& hashval = ascon.Ascon_Hash(message);

	show("message", message);
	show("tag", hashval);
}

int main() {
	test_ende();
	test_hash();
	return 0;
}
