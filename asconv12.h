#ifndef __ASCONV12_H__
#define __ASCONV12_H__

#include <vector>
#include <iostream>
namespace ASCONV12 {
	// 定义数据类型
	using ascon_8 = unsigned char;
	using ascon_64 = unsigned long long int;
	using ascon_data = std::vector<ascon_8>;

	using ascon_state = std::vector<ascon_64>;
	using ascon_padding = std::vector<ascon_64>;

	using permutations_type = int;




	class ascon_128 {
	public:
		ascon_128();
		ascon_128(ascon_64, ascon_64);
		ascon_64 high, low;
		void copyto64(ascon_64& a, ascon_64& b) const;
		void xorwith64(ascon_64& a, ascon_64& b) const;
		void showhex(std::ostream& out) const;
		bool operator==(const ascon_128& tmp)const;
	};


	class Asconv12 {
	public:
		Asconv12();
		static void encryption(const ascon_data& plaintext, const ascon_data& associatedData, ascon_data& ciphertext, const ascon_128& keys, const ascon_128& nonce, ascon_128& T);
		static bool decryption(const ascon_data& ciphertext, const ascon_data& asconciatedData, ascon_data& plaintext, const ascon_128& keys, const ascon_128& nonce, ascon_128& T);
	private:
		static void padding(const ascon_data& data, ascon_padding& out, bool need = true);
		static void permutations(permutations_type t, ascon_state &S);

		// 循环右移
		static ascon_64 ROTR(ascon_64 d, int n);

		// 过程
		static void Initalization(ascon_state& S, const ascon_128& keys, const ascon_128& nonce);
		static void ProcessingAssociatedData(ascon_state& S, ascon_padding& A, const ascon_data& associatedData);
		static void ProcessingPlaintext(ascon_state& S, ascon_padding& P, ascon_padding& C, const ascon_data& plaintext, ascon_data& ciphertext);
		static void ProcessingCiphertext(ascon_state& S, ascon_padding& C, ascon_padding& P, const ascon_data& ciphertext, ascon_data& plaintext);
		static bool Finalization(ascon_state& S, const ascon_128& keys, ascon_128& T, const ascon_128& Ttmp = { 0, 0 });

		static void transform(const ascon_padding& in, ascon_data& out, size_t l);

		// 定义常量数据
		static const permutations_type a = 12;
		static const permutations_type b = 6;

		static const int k = 128;
		static const int r = 64;
		static const int c = 256;
	};

};

#endif
