#!/usr/bin/python3
# Calculate a hash extension from a given hash state.
#
# Copyright 2012 Thomas Skora <thomas@skora.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import re
import struct
import binascii
import urllib.parse
import base64

debug=False

def debugprint(msg):
    if debug:
        print(msg)

class sha1:
    # the SHA1 hash algorithm according to RFC 3174
    blocksize = 64
    # ch. 6.1
    H = [bytes.fromhex('67452301')] + [bytes.fromhex('EFCDAB89')] + [bytes.fromhex('98BADCFE')] + [bytes.fromhex('10325476')] + [bytes.fromhex('C3D2E1F0')]
    K = [0x5A827999] * 20 + [0x6ED9EBA1] * 20 + [0x8F1BBCDC] * 20 + [0xCA62C1D6] * 20

    # initialize length and iv
    def __init__(self, iv=None, length=0):
        
        if iv:
            if not re.match('^[0-9a-f]{40}$', iv, re.I):
                raise ValueError("IV for SHA1 must be a hex string of length 40")
            for i in range(0,5):
                o = i * 8
                self.H[i] = bytes.fromhex(iv[o:o+8])
        self.l = length
        debugprint("sha1.__init__: object initialized with l=" + str(self.l) + " iv=" + str(binascii.hexlify(b''.join(self.H)), "ascii"))

    # adds padding to message. if l is given it is used, else the l of the object instance is used.
    # ul is the number of unknown bytes which prepend the current block. It is used to shorten the padding
    # appropriately.
    def pad(self, msg, ul=0, l=None):
        if l == None:
            l = self.l
        debugprint("sha1.pad: length is " + str(self.l) + " msg=" + repr(msg) + " ul=" + str(ul))
        if (len(msg) + ul) % 64 > 55:        # padding doesn't fits in remaining block, add pad-only block
            msg = msg + b'\x80' + b'\x00' * (64 - 1 - ((len(msg) + ul) % 64) + 56) + struct.pack(">Q", self.l * 8)
        else:                         # padding fits in one block
            msg = msg + b'\x80' + b'\x00' * (64 - 8 - 1 - ((len(msg) + ul) % 64)) + struct.pack(">Q", self.l * 8)
        debugprint("sha1.pad: msg after padding=" + repr(msg) + " length=" + str(len(msg)))
        return msg

    # ch. 5
    def f(self, t,B,C,D):
        if t in range(0,20):
            return (B & C) | ((~B) & D)
        elif t in range(20,40):
            return B ^ C ^ D
        elif t in range(40,60):
            return (B & C) | (B & D) | (C & D)
        elif t in range(60,80):
            return B ^ C ^ D
        else:
            raise IndexError

    # ch. 3, circular left shift
    def S(self, n, x):
        return ((x << n) | (x >> (32 - n))) & 0xffffffff

    # ch 6.1
    def process_block(self, m):
        # a. (converts chunks into int's since arithmetic operations follow)
        w = [int.from_bytes(m[i:i+4], 'big') for i in range(0, 64, 4)] + [0] * 64
        debugprint("sha1.process_block: a. w=" + repr(w))

        # b.
        for t in range(16, 80):
            w[t] = self.S(1, w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16])
        debugprint("sha1.process_block: b. w=" + repr(w))

        # c.
        (a,b,c,d,e) = [int.from_bytes(x, 'big') for x in self.H]
        debugprint("sha1.process_block: c. a=" + str(a) + " b=" + str(b) + " c=" + str(c) + " d=" + str(d) + " e=" + str(e))

        # d.
        for t in range(0, 80):
            temp = (self.S(5, a) + self.f(t, b, c, d) + e + w[t] + self.K[t]) % 2**32
            e = d
            d = c
            c = self.S(30, b)
            b = a
            a = temp
            debugprint("sha1.process_block: d. t=" + str(t) + " a=" + str(a) + " b=" + str(b) + " c=" + str(c) + " d=" + str(d) + " e=" + str(e))

        # e.
        self.H[0] = ((int.from_bytes(self.H[0], 'big') + a) % 2**32).to_bytes(4, 'big')
        self.H[1] = ((int.from_bytes(self.H[1], 'big') + b) % 2**32).to_bytes(4, 'big')
        self.H[2] = ((int.from_bytes(self.H[2], 'big') + c) % 2**32).to_bytes(4, 'big')
        self.H[3] = ((int.from_bytes(self.H[3], 'big') + d) % 2**32).to_bytes(4, 'big')
        self.H[4] = ((int.from_bytes(self.H[4], 'big') + e) % 2**32).to_bytes(4, 'big')
        debugprint("sha1.process_block: e. H=" + str(binascii.hexlify(b''.join(self.H)), "ascii"))
        
    # continue calculation of given state
    def add(self, m):
        self.l += len(m)
        m = self.pad(m)
        assert len(m) % 64 == 0
        
        for i in range(0, len(m), 64):
            block = m[i:i+64]
            debugprint("sha1.add: Processing block: " + repr(block) + " length: " + str(len(block)))
            self.process_block(block)

    # return binary representation of hash
    def digest(self):
        return b''.join(self.H)

    def hexdigest(self):
        return str(binascii.hexlify(self.digest()), "ascii")

##### main functions #####
def calchash(hashclass, hashstate, length, msg):
    h = hashclass(hashstate, length)
    h.add(msg)
    return h.hexdigest()

def extendhash(hashclass, hashstate, unknown_length, previous, extension):
    h = hashclass(hashstate, unknown_length + len(previous))
    prevhashed = h.pad(previous, unknown_length)
    newpayload = prevhashed + extension
    h.l = len(prevhashed) + unknown_length
    h.add(extension)
    newhash = h.hexdigest()
    return (newpayload, newhash)
    
##### main #####
argparser = argparse.ArgumentParser(
    description = 'Perform a hash extension attack on a given hash state.',
    fromfile_prefix_chars = '@'
    )
argparser.add_argument(
    '-m', '--mode',
    default = 'extend',
    choices = {'hash', 'extend'},
    help = 'Mode of operation. hash=calculate hash from optionally given start state extend=calculate hash extension from given state (default: %(default)s)'
    )
argparser.add_argument(
    '-f', '-hash',
    dest = 'hash',
    default = 'sha1',
    choices = {'sha1'},
    help = 'Hash function used for calculations (default: %(default)s)'
    )
argparser.add_argument(
    '-e', '--extension', '--value',
    required = True,
    help = 'The extension for which the attack is performed. In hash mode the value which should be hashed.'
    )
argparser.add_argument(
    '-p', '--previous',
    help = 'Previously hashed known value. Mandatory in hash extension mode.'
    )
argparser.add_argument(
    '-b', '--binary',
    action = 'store_true',
    help = 'Extension and previous value is given in hex format (e.g. deadbeef) and is converted into bytes.'
    )
argparser.add_argument(
    '-s', '--hashstate',
    help = 'Start state of the hash function in hex format (e.g. deadbeef). In normal hash extension attacks this would be the hash from which the extension should be calculated. Mandatory in hash extension mode.'
    )
argparser.add_argument(
    '-u', '--unknown-length',
    type = int,
    default = 0,
    help = 'Length of unknown value. Mandatory in hash extension mode.'
    )
argparser.add_argument(
    '-mu', '--max-unknown-length',
    type = int,
    default = 0,
    help = 'Maximum length of unknown value. If this is given, hash extension iterates between unknown-length and max-unknown-length.'
    )
argparser.add_argument(
    '-l', '--length',
    type = int,
    default = 0,
    help = 'Initialize hash function with length of already hashed value.'
    )
argparser.add_argument(
    '-of', '--output-format',
    default = 'python',
    choices = {'python', 'url', 'hex', 'base64'},
    help = 'Output format of new payload. Possible values: python=Python repr(), url=URL encoded, hex=hexadecimal representation, base64=military-grade high security encryption (default: %(default)s)'
    )
argparser.add_argument(
    '-po', '--payload-output',
    help = 'Output file for new payloads'
    )
argparser.add_argument(
    '-ho', '--hash-output',
    help = 'Output file for new hash'
    )
argparser.add_argument(
    '-d', '--debug',
    action = 'store_true',
    help = 'Verbose debugging output.'
    )
args = argparser.parse_args()
debug = args.debug

if args.mode == 'extend' and (args.previous == None or args.hashstate == None or args.unknown_length == 0):
    argparser.error("Mode 'extend' requires previous, hashstate and unknown-length parameter!")

hashclass = eval(args.hash)
if args.binary:
    args.extension = bytes.fromhex(args.extension)
    if args.previous != None:
        args.previous = bytes.fromhex(args.previous)
else:
    args.extension = bytes(args.extension, "ascii")
    if args.previous != None:
        args.previous = bytes(args.previous, "ascii")

if args.mode == 'hash':
    print(calchash(hashclass, args.hashstate, args.length, args.extension))
elif args.mode == 'extend':
    if (args.max_unknown_length < args.unknown_length):
        args.max_unknown_length = args.unknown_length + 1

    pf = None
    hf = None
    if args.payload_output:
        pf = open(args.payload_output, mode="w")
    if args.hash_output:
        hf = open(args.hash_output, mode="w")

    for unknown_length in range(args.unknown_length, args.max_unknown_length):
        (newpayload, newhash) = extendhash(hashclass, args.hashstate, unknown_length, args.previous, args.extension)

        if args.output_format == 'python':
            newpayload = repr(newpayload)
        elif args.output_format == 'url':
            newpayload = urllib.parse.quote(newpayload)
        elif args.output_format == 'hex':
            newpayload = str(binascii.hexlify(newpayload), "ascii")
        elif args.output_format == 'base64':
            newpayload = str(base64.b64encode(newpayload), "ascii")
        
        print("New payload: " + newpayload)
        if pf:
            print(newpayload, file=pf)
        print("New hash: " + newhash)
    if hf:
        print(newhash, file=hf)

    if pf:
        pf.close()
    if hf:
        hf.close()
