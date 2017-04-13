/*
This file is part of SHA256
Copyright (C) 2017 @maldevel
https://github.com/maldevel/SHA256

Calculate SHA 256 with CryptoAPI and C.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

For more see the file 'LICENSE' for copying permission.
*/

#include "hash.h"

#pragma comment(lib,"advapi32.lib")

static void hZero(void *mem, unsigned long size)
{
	if (size <= 0)return;

	if (mem) {
		SecureZeroMemory(mem, size);
	}
}

static void* hAlloc(unsigned long size)
{
	if (size <= 0) return NULL;

	HANDLE processHeap = GetProcessHeap();
	if (processHeap == NULL)return NULL;

	return HeapAlloc(processHeap, HEAP_ZERO_MEMORY, size);
}

static void hFree(void *mem)
{
	if (mem == NULL) return;

	HANDLE processHeap = GetProcessHeap();
	if (processHeap == NULL)return;

	HeapFree(processHeap, 0, mem);
	mem = NULL;
}

static void sha256_free(sha256_context *ctx)
{
	if (ctx->hCryptProv)
	{
		CryptReleaseContext(ctx->hCryptProv, 0);
		ctx->hCryptProv = 0;
	}

	if (ctx->hHash)
	{
		CryptDestroyHash(ctx->hHash);
		ctx->hHash = 0;
	}
}

static int FormatString(char *destination, const unsigned int sizeInBytes, const char* format, ...)
{
	if (destination == NULL || sizeInBytes <= 0 || format == NULL) return -1;

	int result = -1;

	va_list argList;
	va_start(argList, format);
	result = _vsnprintf_s(destination, sizeInBytes, _TRUNCATE, format, argList);
	va_end(argList);

	return result;
}

static HRESULT ConcatString(char *destination, unsigned int sizeInBytes, const char *source)
{
	if (destination == NULL || sizeInBytes <= 0 || source == NULL) return S_FALSE;

	return strncat_s(destination, sizeInBytes, source, _TRUNCATE) == 0 ? S_OK : S_FALSE;
}

static bool sha256_init(sha256_context *ctx)
{
	hZero(ctx, sizeof(sha256_context));

	if (CryptAcquireContext(&ctx->hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) == FALSE)
	{
		return false;
	}

	if (CryptCreateHash(ctx->hCryptProv, CALG_SHA_256, 0, 0, &ctx->hHash) == FALSE)
	{
		sha256_free(ctx);
		return false;
	}

	return true;
}

static bool sha256_update(sha256_context *ctx, const unsigned char *input, unsigned long ilen)
{
	if (!ctx->hHash) return false;

	if (CryptHashData(ctx->hHash, input, ilen, 0) == FALSE)
	{
		sha256_free(ctx);
		return false;
	}

	return true;
}

static bool sha256_finish(sha256_context *ctx, unsigned char *output)
{
	if (!ctx->hHash) return false;
	unsigned long size = SHA256_HASH_SIZE;

	if (CryptGetHashParam(ctx->hHash, HP_HASHVAL, output, &size, 0) == FALSE)
	{
		sha256_free(ctx);
		return false;
	}

	sha256_free(ctx);

	return true;
}

bool LibHash::sha256(const unsigned char *input, unsigned long ilen, unsigned char *output)
{
	sha256_context ctx;

	if (!sha256_init(&ctx)) return false;
	if (!sha256_update(&ctx, input, ilen)) return false;
	if (!sha256_finish(&ctx, output)) return false;

	return true;
}

bool LibHash::sha256(const unsigned char *input, unsigned long ilen, char **output)
{
	unsigned char tmp[SHA256_HASH_SIZE];
	char part[3] = { 0 };
	int outputSize = (SHA256_HASH_SIZE * 2) + 1;

	if (!sha256(input, ilen, tmp)) {
		return false;
	}

	if ((*output = (char*)hAlloc(outputSize * sizeof(char))) == NULL) {
		return false;
	}

	for (int i = 0; i < SHA256_HASH_SIZE; i++)
	{
		if (FormatString(part, 3, "%02x", tmp[i]) == -1) {
			hFree(*output);
			return false;
		}

		if (ConcatString(*output, outputSize, part) == S_FALSE) {
			hFree(*output);
			return false;
		}
	}

	return true;
}
