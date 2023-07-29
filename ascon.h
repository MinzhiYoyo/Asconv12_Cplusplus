#ifndef __ASCON__H__
#define __ASCON__H__

#include <vector>

namespace ASCON {

	using ascon8bits = unsigned char;
	using ascon_data = std::vector<ascon8bits>;

	using ascon64bits = unsigned long long int;
	using ascon_padding = std::vector<ascon64bits>;

	using ascon128bits = ascon64bits[2];

	using ascon256bits = ascon64bits[4];

	class Ascon {
	public:
		const ascon_data& Encryption(const ascon_data&, const ascon_data&, const ascon128bits&, const ascon128bits&, ascon128bits&);
		const ascon_data& Decryption(const ascon_data&, const ascon_data&, const ascon128bits&, const ascon128bits&, const ascon128bits&);
		const ascon256bits& Ascon_Hash(const ascon_data&);
	private:
		ascon256bits H;
		ascon64bits S[5];  // S[0] is Sr
		ascon_data Plaintext, Ciphertext;
		ascon128bits K, N, T;
		void Permuation(int);
		static void Padding(ascon_padding&,const ascon_data&);
		void Initalization();
		void ProcessingAssociatedData(const ascon_data&);
		void ProcessingPlaintext(const ascon_data&);
		void ProcessingCiphertext(const ascon_data&);
		bool Finalization(bool);  // 返回解密成功的标志
	};
}

#endif

