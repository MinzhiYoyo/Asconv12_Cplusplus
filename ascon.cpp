#include "ascon.h"

namespace ASCON {
	const int a = 12;
	const int b = 6;
	const int r = 64;

	const int ha = 12;
	const int hb = 12;
	
	ascon64bits ROTR(ascon64bits d, int t) {
		return ((d << (64 - t)) | (d >> t));
	}

	void Transfer(ascon_padding& p, ascon_data& d, int n) {
		d.clear();
		d.resize(n);

		for (int i = 0; i < p.size(); i++) {
			for (int j = 0; j < 8 && 8*i + j < n; j++) {
				d[8 * i + j] = (ascon8bits)(p[i] >> (64 - (j + 1) * 8));
			}
		}
	}


	// 加密
	const ascon_data& Ascon::Encryption(const ascon_data& plaintext, const ascon_data& associatedata, const ascon128bits& Key, const ascon128bits& Nonce, ascon128bits& Tag) {
		// 加密过程赋值
		K[0] = Key[0]; K[1] = Key[1];
		N[0] = Nonce[0]; N[1] = Nonce[1];

		this->Initalization();
		this->ProcessingAssociatedData(associatedata);
		this->ProcessingPlaintext(plaintext);
		this->Finalization(true);

		// 返回标志T
		Tag[0] = T[0]; Tag[1] = T[1];
		return this->Ciphertext;
	}

	// 解密
	const ascon_data& Ascon::Decryption(const ascon_data& ciphertext, const ascon_data& associatedata, const ascon128bits& Key, const ascon128bits& Nonce, const ascon128bits& Tag) {
		// 解密过程赋值
		K[0] = Key[0]; K[1] = Key[1];
		N[0] = Nonce[0]; N[1] = Nonce[1];
		T[0] = Tag[0]; T[1] = Tag[1];

		this->Initalization();
		this->ProcessingAssociatedData(associatedata);
		this->ProcessingCiphertext(ciphertext);
		bool flag = this->Finalization(false);

		if (!flag) this->Plaintext.clear();
		return this->Plaintext;
	}

	// 哈希
	const ascon256bits& Ascon::Ascon_Hash(const ascon_data& msg){
		// 初始化
		S[0] = 0x00400c0000000100; S[1] = 0; S[2] = 0; S[3] = 0; S[4] = 0;
		this->Permuation(ha);

		// 吸收数据
		ascon_padding M;
		Padding(M, msg);
		if (msg.empty()) M = { 0x8000000000000000 };
		for (int i = 0; i < M.size(); ++i) {
			S[0] ^= M[i];
			if (i != M.size() - 1) {
				this->Permuation(hb);
			}
		}

		// 压缩哈希
		this->Permuation(ha);
		for (int i = 0; i < 4; i++) {
			H[i] = S[0];
			this->Permuation(hb);
		}

		// 返回哈希值
		return H;
	}


	void Ascon::Initalization() {
		/*S[0] = 0; S[1] = 0; S[2] = 0; S[3] = 0; S[4] = 0;*/
		S[0] = 0x80400c0600000000; // Ⅳ
		S[1] = K[0];
		S[2] = K[1];
		S[3] = N[0];
		S[4] = N[1];

		this->Permuation(a);
		S[3] ^= K[0];
		S[4] ^= K[1];
	}

	// 处理关联数据
	void Ascon::ProcessingAssociatedData(const ascon_data& A_data) {
		ascon_padding A;
		Ascon::Padding(A, A_data);
		for (int i = 0; i < A.size(); ++i) {
			S[0] ^= A[i];
			this->Permuation(b);
		}
		S[4] ^= 1;
	}

	// 处理明文
	void Ascon::ProcessingPlaintext(const ascon_data& P_data) {
		ascon_padding P;
		Ascon::Padding(P, P_data);
		ascon_padding C(P.size(), 0);
		
		for (int i = 0; i < P.size(); ++i) {
			C[i] = S[0] ^ P[i];
			S[0] = C[i];
			if(i != P.size()-1)
				this->Permuation(b);
		}
		// ascon_padding 转成 ascon_data
		Transfer(C, Ciphertext, P_data.size());
	}
	// 处理密文
	void Ascon::ProcessingCiphertext(const ascon_data& C_data) {
		ascon_padding C;
		Ascon::Padding(C, C_data);
		ascon_padding P(C.size(), 0);
		for (int i = 0; i < C.size() - 1; ++i) {
			P[i] = S[0] ^ C[i];
			S[0] = C[i];
			this->Permuation(b);
		}
		P[C.size()-1] = S[0] ^ C[C.size() - 1];
		int l = C_data.size() % r * 8;
		S[0] = C.back() ^ (S[0] << l >> l);  // 这一步
		Transfer(P, Plaintext, C_data.size());
	}

	// 终止化
	bool Ascon::Finalization(bool isEn){
		S[1] ^= K[0];
		S[2] ^= K[1];
		this->Permuation(a);
		if (isEn) {  // 加密
			T[0] = K[0] ^ S[3];
			T[1] = K[1] ^ S[4];
		}
		else {  // 解密
			return T[0] == (K[0] ^ S[3]) and T[1] == (K[1] ^ S[4]);
		}
		return true;
	}

	void Ascon::Permuation(int t) {
		ascon64bits x0 = S[0], x1 = S[1], x2 = S[2], x3 = S[3], x4 = S[4], t0, t1, t2, t3, t4;
		for (ascon64bits i = 12 - t; i < 12; ++i) {
			// pC层
			x2 ^= ( ((ascon64bits)0xf - i) << 4 ) | i;

			// pS层
			x0 ^= x4;    x4 ^= x3;    x2 ^= x1;
			t0 = x0;     t1 = x1;     t2 = x2;     t3 = x3;     t4 = x4;
			t0 = ~t0;    t1 = ~t1;    t2 = ~t2;    t3 = ~t3;    t4 = ~t4;
			t0 &= x1;    t1 &= x2;    t2 &= x3;    t3 &= x4;    t4 &= x0;
			x0 ^= t1;    x1 ^= t2;    x2 ^= t3;    x3 ^= t4;    x4 ^= t0;
			x1 ^= x0;    x0 ^= x4;    x3 ^= x2;    x2 = ~x2;

			// pL层
			x0 ^= ROTR(x0, 19) ^ ROTR(x0, 28);
			x1 ^= ROTR(x1, 61) ^ ROTR(x1, 39);
			x2 ^= ROTR(x2, 1) ^ ROTR(x2, 6);
			x3 ^= ROTR(x3, 10) ^ ROTR(x3, 17);
			x4 ^= ROTR(x4, 7) ^ ROTR(x4, 41);
		}
		S[0] = x0; S[1] = x1; S[2] = x2; S[3] = x3; S[4] = x4;
	}

	void Ascon::Padding(ascon_padding& out,const ascon_data& d) {
		out.clear();
		if(d.empty()){
			return;
		}

		int outsize = d.size() * 8 / 64 + 1;
		out.resize(outsize);
		std::fill(out.begin(), out.end(), 0);

		// 前outsize-1项
		for (int i = 0; i < outsize - 1; ++i) {
			for (int j = 0; j < 8; j++){
				out[i] <<= 8;
				out[i] |= d[8 * i + j];
			}	
		}

		// 最后一项
		for (int i = 0; i < 8; i++) {
			out[outsize - 1] <<= 8;
			int index = 8 * (outsize - 1) + i;
			if (index < d.size()) {
				out[outsize - 1] |= (ascon64bits)d[index];
			}
			else if (index == d.size()) {
				out[outsize - 1] |= (ascon64bits)0x80;
			}
		}
	}

}
