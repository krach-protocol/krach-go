package krach

/*
Taken from https://github.com/flynn/noise

Flynn® is a trademark of Prime Directive, Inc.

Copyright (c) 2015 Prime Directive, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Prime Directive, Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

import (
	"crypto/hmac"
	"hash"
)

func hkdf(h func() hash.Hash, outputs int, out1, out2, out3, chainingKey, inputKeyMaterial []byte) ([]byte, []byte, []byte) {
	if len(out1) > 0 {
		panic("len(out1) > 0")
	}
	if len(out2) > 0 {
		panic("len(out2) > 0")
	}
	if len(out3) > 0 {
		panic("len(out3) > 0")
	}
	if outputs > 3 {
		panic("outputs > 3")
	}

	tempMAC := hmac.New(h, chainingKey)
	tempMAC.Write(inputKeyMaterial)
	tempKey := tempMAC.Sum(out2)

	out1MAC := hmac.New(h, tempKey)
	out1MAC.Write([]byte{0x01})
	out1 = out1MAC.Sum(out1)

	if outputs == 1 {
		return out1, nil, nil
	}

	out2MAC := hmac.New(h, tempKey)
	out2MAC.Write(out1)
	out2MAC.Write([]byte{0x02})
	out2 = out2MAC.Sum(out2)

	if outputs == 2 {
		return out1, out2, nil
	}

	out3MAC := hmac.New(h, tempKey)
	out3MAC.Write(out2)
	out3MAC.Write([]byte{0x03})
	out3 = out3MAC.Sum(out3)

	return out1, out2, out3
}
