#!/usr/bin/env python
# -*- coding: utf8 -*-


import MFRC522
import sys
import getopt
import re
import time
from dataclasses import dataclass
from Anticol import anticol, auto_find_port, print_hex

from MFClassic import GUESS_KEYS, is_trailer_block


PACKAGE_VERSION = '0.10.7(0.0.1)'

MEM_CHUNK = 10000
TRY_KEYS = 50

# Number of trailers == number of sectors
# Mifare Classic 1k 16x64b = 16
NR_TRAILERS_1k = 16

# Mifare Classic Mini
NR_TRAILERS_MINI = 5

# Mifare Classic 4k 32x64b + 8*256b = 40
NR_TRAILERS_4k = 40

# Mifare Classic 2k 32x64b
NR_TRAILERS_2k = 32

# Number of blocks
# Mifare Classic 1k
NR_BLOCKS_1k = 0x3f

# Mifare Classic Mini
NR_BLOCKS_MINI = 0x13

# Mifare Classic 4k
NR_BLOCKS_4k = 0xff

# Mifare Classic 2k
NR_BLOCKS_2k = 0x7f

MAX_FRAME_LEN = 264

# Used for counting nonce distances, explore [nd-value, nd+value]
DEFAULT_TOLERANCE = 20

# Default number of distance probes
DEFAULT_DIST_NR = 15

# Default number of probes for a key recovery for one sector
DEFAULT_PROBES_NR = 150

# Number of sets with 32b keys
DEFAULT_SETS_NR = 5

KEY_REGEX = '([0-9A-Fa-f]{12})'


@dataclass
class Denonce:
    distances: list
    dedian: int
    num_distances: int
    tolerance: int
    parity: list


@dataclass
class Sector:
    keyA: list = None
    keyB: list = None
    found_keyA: bool = False
    found_keyB: bool = False
    trailer: int = 0


@dataclass
class MfTag:
    sectors: list = None
    e_sector: Sector = None
    num_sectors: int = 0
    num_blocks: int = 0
    auth_uid: list = None


def usage(exit_code):
  print(
      "Usage: mfoc [-h] [-k key] [-f file] ... [-P probnum] [-T tolerance] [-O output]\n")
  print("  h     print this help and exit")
  print("  k     try the specified key in addition to the default keys")
  print("  f     parses a file of keys to add in addition to the default keys ")
  print("  P     number of probes per sector, instead of default of 20")
  print("  T     nonce tolerance half-range, instead of default of 20\n        (i.e., 40 for the total range, in both directions)")
  print("  O     file in which the card contents will be written (REQUIRED)")
  print("  D     file in which partial card info will be written in case PRNG is not vulnerable\n")
  print("Example: mfoc -O mycard.mfd")
  print("Example: mfoc -k ffffeeeedddd -O mycard.mfd")
  print("Example: mfoc -f keys.txt -O mycard.mfd")
  print("Example: mfoc -P 50 -T 30 -O mycard.mfd\n")
  print("This is mfoc version %s." % PACKAGE_VERSION)
  print("For more information, run: 'man mfoc'.")

  exit(exit_code)


def str_to_key(str):
    return [int(str[0:2], 16), int(str[2:4], 16), int(str[4:6], 16), int(str[6:8], 16), int(str[8:10], 16), int(str[10:12], 16)]


def re_anticol(mf_reader: MFRC522):
    # Try to anticol again.
    mf_reader.MFRC522_HaltA()
    mf_reader.antennaOff()
    mf_reader.antennaOn()
    (success, _) = anticol(mf_reader, print_info=False, wakeup=True, no_rats=True)
    if not success:
        print('Tag has been removed')
        exit(-1)


def main():
    d = Denonce(None, 0, DEFAULT_DIST_NR, DEFAULT_TOLERANCE, [0x00, 0x00, 0x00])
    t = MfTag()

    optlist, args = getopt.getopt(sys.argv[1:], 'hD:s:BP:T:S:O:k:t:f:')
    
    fp_dump = None
    fp_key = None

    customer_keys = []

    for (opt_key, opt_value) in optlist:
        if opt_key == '-P':
            probes = int(opt_value)
            if probes < 1:
                print('The number of probes must be a positive number')
                exit(-1)
        elif opt_key == '-T':
            res = int(opt_value)
            if res < 0:
                print('The nonce distances range must be a zero or a positive number')
                exit(-1)
            d.tolerance = res
        elif opt_key == '-f':
            try:
                with open(opt_value, 'r') as fp:
                    lines = fp.readlines()
                    for line in lines:
                        key_match = re.match(KEY_REGEX, line)
                        if key_match is not None:
                            customer_keys.append(str_to_key(key_match.group(1)))
                            print('The custom key 0x%s has been added to the default keys' % key_match.group(1))
            except IOError as err:
                print('Cannot open keyfile: %s, err = %s, exiting' % (opt_value, err))
                exit(-1)
        elif opt_key == '-k':
            key_match = re.match(KEY_REGEX, opt_value)
            if key_match is not None:
                customer_keys.append(str_to_key(key_match.group(1)))
                print('The custom key 0x%s has been added to the default keys' % key_match.group(1))
            else:
                print('Custom key %s invalid, ignored' % opt_value)
        elif opt_key == '-O':
            # File output
            try:
                fp_dump = open(opt_value, 'wb')
            except IOError as err:
                print('Cannot open output file: %s, err = %s, exiting' % (opt_value, err))
                exit(-1)
        elif opt_key == '-D':
            # Partial file output
            try:
                fp_key =  open(opt_value, 'wb')
            except IOError as err:
                print('Cannot open key file: %s, err = %s, exiting' % (opt_value, err))
                exit(-1)
        elif opt_key == '-h':
            usage(0)
        else:
            usage(1)
    
    if fp_dump is None:
        print('Parameter -O is mandatory')
        exit(-1)

    port = auto_find_port()
    mf_reader = MFRC522.MFRC522(dev=port)
    
    (success, card_info) = anticol(mf_reader, no_rats=True)
    if not success:
        print('No tag found')
        exit(-1)

    (uid, sak, atqa, ats) = card_info
    if sak & 0x08 == 0 and sak != 0x01:
        print('Only Mifare Classic is supported')
        exit(-1)

    # Use last full bytes.
    t.auth_uid = uid[-4:]

    if sak in [0x01, 0x08, 0x88, 0x28]:
        # Check if MIFARE Plus 2K
        if ats is not None and len(ats) >= 10 and ats[5:9] == [0xc1, 0x05, 0x2f, 0x2f] and (atqa[1] & 0x02 == 0):
            print('Found Mifare Plus 2k tag')
            t.num_sectors = NR_TRAILERS_2k
            t.num_blocks = NR_BLOCKS_2k
        else:
            print('Found Mifare Classic 1k tag')
            t.num_sectors = NR_TRAILERS_1k
            t.num_blocks = NR_BLOCKS_1k
    elif sak == 0x09:
        print('Found Mifare Classic Mini tag')
        t.num_sectors = NR_TRAILERS_MINI
        t.num_blocks = NR_BLOCKS_MINI
    elif sak == 0x18:
        print('Found Mifare Classic 4k tag')
        t.num_sectors = NR_TRAILERS_4k
        t.num_blocks = NR_BLOCKS_4k
    else:
        print('Cannot determine card type from SAK')
        exit(-1)
    
    t.sectors = [Sector() for _ in range(t.num_sectors)]
    p_keys = []
    b_keys = []

    d.distances = [0 for _ in range(d.num_distances)]

    print('Try to authenticate to all sectors with default keys...')
    print("Symbols: '.' no key found, '/' A key found, '\\' B key found, 'x' both keys found")

    # Try customer_keys first, than default GUESS_KEYS
    for key in customer_keys + GUESS_KEYS:
        print_hex('[Key: ', key, end='')
        print('] -> [', end='', flush=True)
        i = 0   # Sector counter
        # Iterate over every block, where we haven't found a key yet
        for block in range(t.num_blocks+1):
            if is_trailer_block(block):
                if not t.sectors[i].found_keyA:
                    if mf_reader.MFRC522_Auth(mf_reader.PICC_AUTHENT1A, block, key, t.auth_uid) != mf_reader.MI_OK:
                        # Try to anticol again.
                        re_anticol(mf_reader)
                    else:
                        # Save all information about successfull keyA authentization
                        t.sectors[i].keyA = key
                        t.sectors[i].found_keyA = True
                        # Although KeyA can never be directly read from the data sector, KeyB can, so
                        # if we need KeyB for this sector, it should be revealed by a data read with KeyA
                        # todo - check for duplicates in cracked key list (do we care? will not be huge overhead)
                        # todo - make code more modular! :)
                        if not t.sectors[i].found_keyB:
                            (status, data) = mf_reader.MFRC522_Read(block)
                            if status == mf_reader.MI_OK:
                                keyB = data[1][10:16]
                                if mf_reader.MFRC522_Auth(mf_reader.PICC_AUTHENT1B, block, keyB, t.auth_uid) != mf_reader.MI_OK:
                                    re_anticol(mf_reader)
                                else:
                                    t.sectors[i].keyB = keyB
                                    t.sectors[i].found_keyB = True
                                    b_keys.append(keyB)
                            else:
                                # Try to anticol again.
                                re_anticol(mf_reader)
                # if key reveal failed, try other keys
                if not t.sectors[i].found_keyB:
                    if mf_reader.MFRC522_Auth(mf_reader.PICC_AUTHENT1B, block, key, t.auth_uid) != mf_reader.MI_OK:
                        # Try to anticol again.
                        re_anticol(mf_reader)
                        # No success, try next block
                        t.sectors[i].trailer = block
                    else:
                        t.sectors[i].keyB = key
                        t.sectors[i].found_keyB = True
                if t.sectors[i].found_keyA and t.sectors[i].found_keyB:
                    print('x', end='', flush=True)
                elif t.sectors[i].found_keyA:
                    print('/', end='', flush=True)
                elif t.sectors[i].found_keyB:
                    print('\\', end='', flush=True)
                else:
                    print('.', end='', flush=True)
                # Save position of a trailer block to sector struct
                t.sectors[i].trailer = block
                i += 1
        print("]")

    print()

    known_key = None
    known_key_letter = None
    known_section = None
    unknown_key_letter = None
    unknown_sector = None
    for i in range(t.num_sectors):
        if t.sectors[i].found_keyA:
            print_hex('Sector %02d - Found   Key A: ' % i, t.sectors[i].keyA, end='')
            known_key = t.sectors[i].keyA
            known_key_letter = 'A'
            known_section = i
        else:
            print('Sector %02d - Unknown Key A                   ' % i, end='', flush=True)
            unknown_key_letter = 'A'
            unknown_sector = i
        if t.sectors[i].found_keyB:
            print_hex(' Sector %02d - Found   Key B: ' % i, t.sectors[i].keyB)
            known_key = t.sectors[i].keyB
            known_key_letter = 'B'
            known_section = i
        else:
            print(' Sector %02d - Unknown Key B' % i)
            unknown_key_letter = 'B'
            unknown_sector = i

    # TODO: Add working logic.

if __name__ == '__main__':
    main()
