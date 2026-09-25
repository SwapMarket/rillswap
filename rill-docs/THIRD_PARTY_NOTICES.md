# Third-party notices

## BIP340 reference implementation

`tests/vendor/bip340_reference.py` is derived from the test-only Python
reference implementation in Bitcoin BIP340 at commit
`f98774a68c23269d9bfa78c8d9c4671ebf4ceb69`.

Source: <https://github.com/bitcoin/bips/blob/f98774a68c23269d9bfa78c8d9c4671ebf4ceb69/bip-0340/reference.py>

The BIP declares its reference code available under BSD-2-Clause, MIT, or
CC0-1.0. RillSwap uses the CC0-1.0 option for this derived test-only copy.

## BIP327 reference implementation

`tests/vendor/bip327_reference.py` is derived from the test-only Python
reference implementation in Bitcoin BIP327 at commit
`acdce4d50c61f81d9ec6534a804b1fb14e84e565`.

Source: <https://github.com/bitcoin/bips/blob/acdce4d50c61f81d9ec6534a804b1fb14e84e565/bip-0327/reference.py>

Copyright (c) 2022 Jonas Nick, Tim Ruffing, and Elliott Jin.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Bitcoin Core v30.0 functional test reference subset

`tests/vendor/bitcoin_core_v30_reference.py` is derived from the Bitcoin Core
v30.0 functional test framework transaction, script, and key helpers.

Sources:

* <https://github.com/bitcoin/bitcoin/blob/v30.0/test/functional/test_framework/messages.py>
* <https://github.com/bitcoin/bitcoin/blob/v30.0/test/functional/test_framework/script.py>
* <https://github.com/bitcoin/bitcoin/blob/v30.0/test/functional/test_framework/key.py>

The source-file notices are:

* `messages.py`: Copyright (c) 2010 ArtForz (public domain half-a-node),
  Copyright (c) 2012 Jeff Garzik, and Copyright (c) 2010-2022 The Bitcoin Core
  developers.
* `script.py`: Copyright (c) 2015-2022 The Bitcoin Core developers.
* `key.py`: Copyright (c) 2019-2020 Pieter Wuille.

The source and this derived test-only subset are licensed under the MIT
License:

Copyright (c) 2009-2025 The Bitcoin Core developers
Copyright (c) 2009-2025 Bitcoin Developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
