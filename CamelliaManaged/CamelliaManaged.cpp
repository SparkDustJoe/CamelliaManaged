#pragma once

#include "CamelliaManaged.h"

using namespace System;
#if _DEBUG
using namespace System::Diagnostics;
#endif

namespace CamelliaManaged
{
	// PRIVATE METHODS
	_key_material^ Camellia::init_key(array<const Byte>^ key)
	{
		if (key == nullptr)
			throw gcnew ArgumentNullException("key");
		if (key->Length != 16 && key->Length != 24 && key->Length != 32)
			throw gcnew ArgumentOutOfRangeException("Key must 128-, 192-, or 256-bit (16, 24, or 32 bytes respectively)");

#ifndef PRECOMPUTED_SBOXES
		initSboxes(); // if the sboxes were not pre-computed, this is where to do that
#endif // !PRECOMPILED_SBOXES

		_key_material^ ret = gcnew _key_material();
		ret->kw = gcnew array<UInt64>(4);
		// KL 128 bit number is split into KL1 (high bits) and KL2 (low bits)
		// KR 128 bit number is split into KR1 (high bits) and KR2 (low bits), but only used for 192- and 256-bit keys
		// Same with KA and KB
		// so anything that is ">> 64" from the spec is the high bits (x1), and "& MASK64" is the low bits(x2)
		UInt64 KL1 = 0, KL2 = 0, KR1 = 0, KR2 = 0;
		UInt64 KA1 = 0, KA2 = 0, KB1 = 0, KB2 = 0;
		UInt64 D1, D2;
		switch(key->Length)
		{
		case 16:
			ret->k = gcnew array<UInt64>(18);
			ret->ke = gcnew array<UInt64>(4);
			BytesToUInt64(KL1, key, 0);
			BytesToUInt64(KL2, key, 8);
			KR1 = KR2 = 0;
			ret->keySizeBits = 128;
			break;
		case 24:
			ret->k = gcnew array<UInt64>(24);
			ret->ke = gcnew array<UInt64>(6);
			BytesToUInt64(KL1, key, 0);
			BytesToUInt64(KL2, key, 8);
			BytesToUInt64(KR1, key, 16);
			KR2 = ~KR1;
			ret->keySizeBits = 192;
			break;
		case 32:
			ret->k = gcnew array<UInt64>(24);
			ret->ke = gcnew array<UInt64>(6);
			BytesToUInt64(KL1, key, 0);
			BytesToUInt64(KL2, key, 8);
			BytesToUInt64(KR1, key, 16);
			BytesToUInt64(KR2, key, 24);
			ret->keySizeBits = 256;
			break;
		}
#if _DEBUG
		Debug::Print("KEY SCHEDULE:=============\r\nKL1             KL2             KR1             KR2");
		Debug::Print(KL1.ToString("x16") + KL2.ToString("x16") + KR1.ToString("x16") + KR2.ToString("x16"));
#endif
		D1 = (KL1 ^ KR1);
		D2 = (KL2 ^ KR2);
		D2 ^= F(D1, Sigma1);
		D1 ^= F(D2, Sigma2);
		D1 ^= (KL1);
		D2 ^= (KL2);
		D2 ^= F(D1, Sigma3);
		D1 ^= F(D2, Sigma4);
		KA1 = D1;
		KA2 = D2;
		if (key->Length > 16) {
			D1 = (KA1 ^ KR1);
			D2 = (KA2 ^ KR2);
			D2 ^= F(D1, Sigma5);
			D1 ^= F(D2, Sigma6);
			KB1 = D1; 
			KB2 = D2;
		}

		if (key->Length == 16)
		{
			// NOTE: ROTATIONS USING RotL128 are permanent/accumulative!
			ret->kw[0] = KL1;
			ret->kw[1] = KL2;
			ret->k[0] = KA1;
			ret->k[1] = KA2;
			RotL128(KL1, KL2, 15); // rotate 128bit left 15  KL
			RotL128(KA1, KA2, 15); // rotate 128bit left 15  KA
			ret->k[2] = KL1;
			ret->k[3] = KL2;
			ret->k[4] = KA1;
			ret->k[5] = KA2;
			RotL128(KA1, KA2, 15); // rotate another 15 left (30 total) KA
			ret->ke[0] = KA1;
			ret->ke[1] = KA2;
			RotL128(KL1, KL2, 30); // rotate another 30 left (45 total) KL
			RotL128(KA1, KA2, 15); // rotate another 15 left (45 total) KA
			ret->k[6] = KL1;
			ret->k[7] = KL2;
			ret->k[8] = KA1;
			RotL128(KL1, KL2, 15); // rotate another 15 left (60 total) KL
			RotL128(KA1, KA2, 15); // rotate another 15 left (60 total) KA
			ret->k[9] = KL2;
			ret->k[10] = KA1;
			ret->k[11] = KA2;
			RotL128(KL1, KL2, 17); // rotate another 17 left (77 total) KL
			ret->ke[2] = KL1;
			ret->ke[3] = KL2;
			RotL128(KL1, KL2, 17); // rotate another 17 left (94 total) KL
			RotL128(KA1, KA2, 34); // rotate another 34 left (94 total) KA
			ret->k[12] = KL1;
			ret->k[13] = KL2;
			ret->k[14] = KA1;
			ret->k[15] = KA2;
			RotL128(KL1, KL2, 17); // rotate another 17 left (111 total) KL
			RotL128(KA1, KA2, 17); // rotate another 17 left (111 total) KA
			ret->k[16] = KL1;
			ret->k[17] = KL2;
			ret->kw[2] = KA1;
			ret->kw[3] = KA2;
		}
		else
		{
			// NOTE: ROTATIONS USING RotL128 are permanent/accumulative!
			ret->kw[0] = KL1;
			ret->kw[1] = KL2;
			ret->k[0] = KB1;
			ret->k[1] = KB2;
			RotL128(KR1, KR2, 15); // rotate 128bit left 15   KR 15
			RotL128(KA1, KA2, 15); // rotate 128bit left 15   KA 15
			ret->k[2] = KR1;
			ret->k[3] = KR2;
			ret->k[4] = KA1;
			ret->k[5] = KA2;
			RotL128(KR1, KR2, 15); // rotate another 15 left (30 total)  KR 30
			RotL128(KB1, KB2, 30); // rotate 128bit left 30 (30 total)  KB 30
			ret->ke[0] = KR1;
			ret->ke[1] = KR2;
			ret->k[6] = KB1;
			ret->k[7] = KB2;
			RotL128(KL1, KL2, 45); // rotate 128bit left 45 (45 total) KL 45
			RotL128(KA1, KA2, 30); // rotate another 30 left (45 total) KA 45
			ret->k[8] = KL1;
			ret->k[9] = KL2;
			ret->k[10] = KA1;
			ret->k[11] = KA2;
			RotL128(KL1, KL2, 15); // rotate another 30 left (60 total) KL 60
			RotL128(KR1, KR2, 30); // rotate another 15 left (60 total) KR 60
			RotL128(KB1, KB2, 30); // rotate another 30 left (60 total) KB 60
			ret->ke[2] = KL1;
			ret->ke[3] = KL2;
			ret->k[12] = KR1;
			ret->k[13] = KR2;
			ret->k[14] = KB1;
			ret->k[15] = KB2;
			RotL128(KL1, KL2, 17); // rotate another 17 left (77 total) KL 77
			RotL128(KA1, KA2, 32); // rotate another 32 left (77 total) KA 77
			ret->k[16] = KL1;
			ret->k[17] = KL2;
			ret->ke[4] = KA1;
			ret->ke[5] = KA2;
			RotL128(KR1, KR2, 34); // rotate another 34 left (94 total) KR 94
			RotL128(KA1, KA2, 17); // rotate another 17 left (94 total) KA 94
			ret->k[18] = KR1;
			ret->k[19] = KR2;
			ret->k[20] = KA1;
			ret->k[21] = KA2;
			RotL128(KL1, KL2, 34); // rotate another 34 left (111 total) KL 111
			RotL128(KB1, KB2, 51); // rotate another xx left (111 total) KB 111
			ret->k[22] = KL1;
			ret->k[23] = KL2;
			ret->kw[2] = KB1;
			ret->kw[3] = KB2;
		}
		return ret;
	}

	UInt64 Camellia::F(UInt64 F_IN, UInt64 KE)
	{
		UInt64 x = F_IN ^ KE;

		array<Byte>^ t = gcnew array<Byte>(8);
		array<Byte>^ y = gcnew array<Byte>(8);
		UInt64ToBytes(t, x, 0);
		
		t[0] = SBox1[t[0]];
		t[1] = SBox2[t[1]];
		t[2] = SBox3[t[2]];
		t[3] = SBox4[t[3]];
		t[4] = SBox2[t[4]];
		t[5] = SBox3[t[5]];
		t[6] = SBox4[t[6]];
		t[7] = SBox1[t[7]];
		y[0] = t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7];
		y[1] = t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7];
		y[2] = t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7];
		y[3] = t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
		y[4] = t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7];
		y[5] = t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7];
		y[6] = t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7];
		y[7] = t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
		t == nullptr; // cleanup

		UInt64 result;
		BytesToUInt64(result, y, 0);
#if _DEBUG
		Debug::Print("Ffunc X=" + F_IN.ToString("x16") + " K=" + KE.ToString("x16") + " Y=" + result.ToString("x16"));
#endif
		return result;
	}

	UInt64 Camellia::FL(UInt64 FL_IN, UInt64 KE)
	{
		UInt32 x1, x2, k1, k2;
		x1 = (UInt32)(FL_IN >> 32);
		x2 = (UInt32)(FL_IN & MASK32);
		k1 = (UInt32)(KE >> 32);
		k2 = (UInt32)(KE & MASK32);
		x2 ^= RotL32((UInt32)(x1 & k1), 1);
		x1 ^= (x2 | k2);
		UInt64 result = ((UInt64)x1 << 32) | x2;
#if _DEBUG
		Debug::Print("FL    X=" + FL_IN.ToString("x16") + " K=" + KE.ToString("x16") + " Y=" + result.ToString("x16"));
#endif
		return result;
	}

	UInt64 Camellia::FLINV(UInt64 FLINV_IN, UInt64 KE)
	{
		UInt32 y1, y2, k1, k2;
		y1 = (UInt32)(FLINV_IN >> 32);
		y2 = (UInt32)(FLINV_IN & 0xFFFFFFFF);
		k1 = (UInt32)(KE >> 32);
		k2 = (UInt32)(KE & MASK32);
		y1 ^= (y2 | k2); 
		y2 ^= RotL32((UInt32)(y1 & k1), 1); 
		UInt64 result = ((UInt64)y1 << 32) | y2;
#if _DEBUG
		Debug::Print("FLinv X=" + FLINV_IN.ToString("x16") + " K=" + KE.ToString("x16") + " Y=" + result.ToString("x16"));
#endif
		return result;
	}

	array<Byte>^ Camellia::proc_block(array<const Byte>^ input, _key_material^ key)
	{
		//encryption and decryption are the same, but the key schedule is inverted

		UInt64 D1, D2;
		BytesToUInt64(D1, input, 0);
		BytesToUInt64(D2, input, 8);
#if _DEBUG
		Debug::Print("PROC_BLOCK:======================================");
#endif
		D1 ^= key->kw[0]; // Prewhitening
		D2 ^= key->kw[1];
		D2 ^= F(D1, key->k[0]); // Round 1
		D1 ^= F(D2, key->k[1]); // Round 2
		D2 ^= F(D1, key->k[2]); // Round 3
		D1 ^= F(D2, key->k[3]); // Round 4
		D2 ^= F(D1, key->k[4]); // Round 5
		D1 ^= F(D2, key->k[5]); // Round 6
		D1 = FL(D1, key->ke[0]); // FL
		D2 = FLINV(D2, key->ke[1]); // FLINV
		D2 ^= F(D1, key->k[6]); // Round 7
		D1 ^= F(D2, key->k[7]); // Round 8
		D2 ^= F(D1, key->k[8]); // Round 9
		D1 ^= F(D2, key->k[9]); // Round 10
		D2 ^= F(D1, key->k[10]); // Round 11
		D1 ^= F(D2, key->k[11]); // Round 12
		D1 = FL(D1, key->ke[2]); // FL
		D2 = FLINV(D2, key->ke[3]); // FLINV
		D2 ^= F(D1, key->k[12]); // Round 13
		D1 ^= F(D2, key->k[13]); // Round 14
		D2 ^= F(D1, key->k[14]); // Round 15
		D1 ^= F(D2, key->k[15]); // Round 16
		D2 ^= F(D1, key->k[16]); // Round 17
		D1 ^= F(D2, key->k[17]); // Round 18
		if (key->keySizeBits > 128)
		{
			D1 = FL(D1, key->ke[4]); // FL
			D2 = FLINV(D2, key->ke[5]); // FLINV
			D2 ^= F(D1, key->k[18]); // Round 19
			D1 ^= F(D2, key->k[19]); // Round 20
			D2 ^= F(D1, key->k[20]); // Round 21
			D1 ^= F(D2, key->k[21]); // Round 22
			D2 ^= F(D1, key->k[22]); // Round 23
			D1 ^= F(D2, key->k[23]); // Round 24
		}
		D2 ^= key->kw[2]; // Postwhitening
		D1 ^= key->kw[3];
		array<Byte>^ output = gcnew array<Byte>(16);
		UInt64ToBytes(output, D2, 0);
		UInt64ToBytes(output, D1, 8);
		return output;
	}

	//PUBLIC METHODS
	array<Byte>^ Camellia::EncryptBlock(array<const Byte>^ data, array<const Byte>^ key)
	{
		if (data == nullptr) throw gcnew ArgumentNullException("data", "must provide data to encrypt");
		if (data->Length != 16) throw gcnew ArgumentOutOfRangeException("data", "data not correctly sized (not 128bits)");
		_key_material^ km = Camellia::init_key(key);
		return Camellia::proc_block(data, km);
	}

	array<Byte>^ Camellia::DecryptBlock(array<const Byte>^ data, array<const Byte>^ key)
	{
		if (data == nullptr) throw gcnew ArgumentNullException("data", "must provide data to decrypt");
		if (data->Length != 16) throw gcnew ArgumentOutOfRangeException("data", "data not correctly sized (not 128bits)");
		_key_material^ km = Camellia::init_key(key);
		if (!km->invert()) return nullptr; // unable to invert key if false is returned
		return Camellia::proc_block(data, km);
	}

}