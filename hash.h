#pragma once

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

#define SHA256_HASH_SIZE	32

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

typedef struct
{
	HCRYPTPROV	hCryptProv;
	HCRYPTHASH	hHash;
}sha256_context;

namespace LibHash
{
	bool sha256(const unsigned char *input, unsigned long ilen, unsigned char *output);
	bool sha256(const unsigned char *input, unsigned long ilen, char **output);
}
