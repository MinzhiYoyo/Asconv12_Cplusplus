#include <iostream>
#include "asconv12.h"
#include <cstdio>
using namespace std;
using namespace ASCONV12;

void show_ascondata(const char * info, const ascon_data& d) {
	cout << info << " = ";
	for (auto& n : d) {
		cout << hex << (int)n;
		//printf_s("%X", d);
	}
	cout << endl;
}

void show_ascon128(const char* info, const ascon_128& d) {
	cout << info << " = ";
	d.showhex(cout);
	cout << endl;
}

void test_encryption(ascon_data& c, ascon_128& T) {
	ascon_128 keys(0, 0);
	ascon_128 nonce(0, 0);
	ascon_data a = { 0x41, 0x53, 0x43, 0x4f, 0x4e };
	ascon_data m = { 0x61, 0x73, 0x63, 0x6f, 0x6e };
	show_ascon128("k", keys);
	show_ascon128("n", nonce);
	show_ascondata("a", a);
	show_ascondata("m", m);
	Asconv12::encryption(m, a, c, keys, nonce, T);
}

void test_decryption(ascon_data& ciphertext, ascon_128& T) {
	ascon_128 keys(0, 0);
	ascon_128 nonce(0, 0);
	ascon_data p;
	ascon_data a = { 0x41, 0x53, 0x43, 0x4f, 0x4e };
	bool flag = Asconv12::decryption(ciphertext, a, p, keys, nonce, T);
	show_ascon128("后T", T);
	show_ascondata("解密文", p);
	cout << flag<< endl;
}

int main() {
	cout << "hello world" << endl;
	ascon_data c;
	ascon_128 T;
	test_encryption(c, T);
	show_ascondata("c", c);
	show_ascon128("T", T);
	cout << "================ 下面解密 ===================" << endl;
	test_decryption(c, T);
	return 0;
}
