#include "asconv12.h"

namespace ASCONV12 {
	ascon_128::ascon_128():high(0), low(0) {
		
	}
	ascon_128::ascon_128(ascon_64 a, ascon_64 b) :high(a), low(b) {
		
	}
	void ascon_128::copyto64(ascon_64& a, ascon_64& b) const {
		a = high;
		b = low;
	}
	void ascon_128::xorwith64(ascon_64& a, ascon_64& b) const {
		a ^= high;
		b ^= low;
	}
	void ascon_128::showhex(std::ostream& out) const {
		out << std::hex << high << low;
	}
	bool ascon_128::operator==(const ascon_128& tmp)const {
		return (tmp.high == this->high) && (tmp.low == this->low);
	}




	// Asconv12
	Asconv12::Asconv12(){}
	void Asconv12::encryption(const ascon_data& plaintext, const ascon_data& associatedData, ascon_data& ciphertext, const ascon_128& keys, const ascon_128& nonce, ascon_128& T) {

		ascon_state S;

		
		// 初始化
		Asconv12::Initalization(S, keys, nonce);
		// 处理关联数据
		Asconv12::ProcessingAssociatedData(S, associatedData);
		// 处理明文
		Asconv12::ProcessingPlaintext(S, plaintext, ciphertext);
		// 终止化
		Asconv12::Finalization(S, keys, T);
	}


	bool Asconv12::decryption(const ascon_data& ciphertext, const ascon_data& assonciatedData, ascon_data& plaintext, const ascon_128& keys, const ascon_128& nonce, ascon_128& T) {
		ascon_state S;


		// 初始化
		Asconv12::Initalization(S, keys, nonce);
		// 处理关联数据
		Asconv12::ProcessingAssociatedData(S, assonciatedData);
		// 处理密文
		Asconv12::ProcessingCiphertext(S, ciphertext, plaintext);
		// 终止化
		ascon_128 Tout;
		bool flag = Asconv12::Finalization(S, keys, Tout, T);

		return flag;
	}

	// 初始化
	void Asconv12::Initalization(ascon_state& S, const ascon_128& keys, const ascon_128& nonce) {
		if (!S.empty())S.clear();
		S.resize(5);
		S[0] = 0x80400c0600000000; // Ⅳ：k || r || a || b || 0^{288-2k}
		keys.copyto64(S[1], S[2]);
		nonce.copyto64(S[3], S[4]);

		Asconv12::permutations(Asconv12::a, S);

		keys.xorwith64(S[3], S[4]);
	}
	// 处理关联数据
	void Asconv12::ProcessingAssociatedData(ascon_state& S, const ascon_data& associatedData) {
		ascon_padding A;
		padding(associatedData, A);
		if (!A.empty()) {
			for (int i = 0; i < A.size(); i++) {
				S[0] ^= A[i];
				Asconv12::permutations(Asconv12::b, S);
			}
			S[4] ^= (ascon_64)0x1;
		}
	}
	// 处理明文
	void Asconv12::ProcessingPlaintext(ascon_state& S, const ascon_data& plaintext, ascon_data& ciphertext) {
		ascon_padding P;
		padding(plaintext, P);
		ascon_padding C(P.size(), 0);
		size_t l = plaintext.size() * 8 % Asconv12::r;
		for (int i = 0; i < P.size(); i++) {
			C[i] = S[0] ^ P[i];
			S[0] = C[i];
			if (i < P.size() - 1) {  // 处理前 t-1 个数据
				Asconv12::permutations(Asconv12::b, S);
			}
			else { // 最后一个数据特殊处理
				C[i] &= ((0xFFFFFFFFFFFFFFFF >> (64 - l)) << (64 - l));
			}
		}

		// ascon_padding transform to ascon_data
		Asconv12::transform(C, ciphertext, l);
	}
	// 处理密文
	void Asconv12::ProcessingCiphertext(ascon_state& S,const ascon_data& ciphertext, ascon_data& plaintext) {
		ascon_padding C; 
		padding(ciphertext, C, false);
		ascon_padding P(C.size(), 0);
		for (int i = 0; i < C.size()-1; i++) {
			P[i] = S[0] ^ C[i];
			S[0] = C[i];
			Asconv12::permutations(Asconv12::b, S);
		}
		int index = C.size() - 1;
		size_t l = ciphertext.size() * 8 % Asconv12::r;
		P[index] = ((S[0] >> (64 - l)) << (64 - l)) ^ C[index];
		S[0] = C[index] | (((S[0] << l) >> l) ^ ((ascon_64)1 << (63 - l)));
		Asconv12::transform(P, plaintext, l);
	}
	// 终止化
	bool Asconv12::Finalization(ascon_state& S, const ascon_128& keys, ascon_128& T, const ascon_128& Ttmp) {
		keys.xorwith64(S[1], S[2]);
		Asconv12::permutations(Asconv12::a, S);
		T.high = S[3] ^ keys.high;
		T.low = S[4] ^ keys.low;
		return T==Ttmp;
	}

	// ascon_padding 转 ascon_data
	// l表示padding最后一个剩余多少位
	void Asconv12::transform(const ascon_padding& in, ascon_data& out, size_t l) { 
		if (!out.empty()) out.clear();
		// output's Bytes
		size_t out_size = ((in.size() - 1) * 64 + l) / 8;
		out.resize(out_size);
		for (int i = 0; i < in.size() - 1; i++) {
			for (int j = 0; j < 8; j++) {
				out[i * 8 + j] = (ascon_8)(in[i] >> ((7 - j) * 8));
			}
		}

		for (int i = 0; i < l / 8; i++) {
			out[8 * (in.size() - 1) + i] = (ascon_8)(in[in.size() - 1] >> ((7 - i) * 8));
		}
	}

	// 全排列
	void Asconv12::permutations(permutations_type t, ascon_state& S) {
		ascon_64 x0 = S[0], x1 = S[1], x2 = S[2], x3 = S[3], x4 = S[4], t0, t1, t2, t3, t4;
		for (ascon_64 i = 12 - t; i < 12; i++) {
			// 常量添加
			x2 ^= (((ascon_64)(0xf) - i) << 4) | i;

			// 替换层
			x0 ^= x4;    x4 ^= x3;    x2 ^= x1;
			t0  = x0;    t1  = x1;    t2  = x2;    t3  = x3;    t4  = x4;
			t0 = ~t0;    t1 = ~t1;    t2 = ~t2;    t3 = ~t3;    t4 = ~t4;
			t0 &= x1;    t1 &= x2;    t2 &= x3;    t3 &= x4;    t4 &= x0;
			x0 ^= t1;    x1 ^= t2;    x2 ^= t3;    x3 ^= t4;    x4 ^= t0;
			x1 ^= x0;    x0 ^= x4;    x3 ^= x2;    x2 = ~x2;

			// 线性扩散层
			x0 ^= Asconv12::ROTR(x0, 19) ^ Asconv12::ROTR(x0, 28);
			x1 ^= Asconv12::ROTR(x1, 61) ^ Asconv12::ROTR(x1, 39);
			x2 ^= Asconv12::ROTR(x2, 1) ^ Asconv12::ROTR(x2, 6);
			x3 ^= Asconv12::ROTR(x3, 10) ^ Asconv12::ROTR(x3, 17);
			x4 ^= Asconv12::ROTR(x4, 7) ^ Asconv12::ROTR(x4, 41);
		}
		S[0] = x0; S[1] = x1; S[2] = x2; S[3] = x3; S[4] = x4;
	}

	// 填充
	void Asconv12::padding(const ascon_data& data, ascon_padding& out, bool need) {
		if (data.size() == 0) return;
		size_t one_zero_Bytes = (Asconv12::r - ((data.size() * 8) % Asconv12::r)) / 8;
		one_zero_Bytes = one_zero_Bytes == 0 ? 1 : one_zero_Bytes;

		size_t size_of_out = need ? (data.size() + one_zero_Bytes) / 8 : (data.size() / 8 + (data.size() % 8 > 0));

		if (!out.empty()) out.clear();
		out.resize(size_of_out);
		std::fill(out.begin(), out.end(), 0);  
		for (size_t i = 0; i < size_of_out - 1; i++) {
			for (int j = 0; j < 8; j++) {
				out[i] <<= 8;
				out[i] |= (ascon_64)data[i * 8 + j];
			}
		}
		for (int i = 0; i < 8; i++) {
			size_t index = (size_of_out - 1) * 8 + i;
			out[size_of_out-1] <<= 8;
			if (index < data.size()) {
				out[size_of_out - 1] |= (ascon_64)data[index];
			}
			else if (index == data.size()) {
				if(need)
					out[size_of_out - 1] |= (ascon_64)0x80;
			}
		}
	}

	// 循环右移动
	ascon_64 Asconv12::ROTR(ascon_64 d, int n) {
		return ((d << (64 - n)) | (d >> n));
	}

};
