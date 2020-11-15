#!/usr/bin/env python
# -*- coding: utf8 -*-

import MFRC522
import sys
from Anticol import anticol, auto_find_port

abt_data = [0x01,  0x23,  0x45,  0x67,  0x00,  0x08,  0x04,  0x00,
            0x46,  0x59,  0x25,  0x58,  0x49,  0x10,  0x23,  0x02,  0x23,  0xeb]
abt_blank = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07,
             0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x36, 0xCC]

def print_hex(prompt, data):
    print(prompt + ' '.join(['%02x' % x for x in data]))


def usage(program_name):
    print('Usage: %s [OPTIONS] [UID|BLOCK0]' % program_name)
    print('Options:')
    print('\t-h\tHelp. Print this message.')
    print('\t-f\tFormat. Delete all data (set to 0xFF) and reset ACLs to default.')
    print('\t-r\tRecovery. Try to recover card event if card does not found.')
    print('\t-l\tLock. Try to lock card after success UID modification, only valid for CUID card.')
    print('\n\tSpecify UID (4 HEX bytes) to set UID, or leave blank for default \'01234567\'.')
    print('\n\tSpecify BLOCK0 (16 HEX bytes) to set content of Block0. CRC (Byte 4) is recalculated an overwritten.')
    print('\tThis utility can be used to recover cards that have been damaged by writing bad')
    print('\tdata (e.g. wrong BCC), thus making them non-selectable by most tools/readers.')
    print('\n\t*** Note: this utility only works with special Mifare 1K cards (Chinese clones).\n')


def main():
    global abt_data
    format = False
    recovery = False
    lock = False
    for argv in sys.argv[1:]:
        if argv == '-h':
            usage(sys.argv[0])
            exit(0)
        elif argv == '-f':
            format = True
        elif argv == '-r':
            recovery = True
        elif argv == '-l':
            lock = True
        elif len(argv) in [8, 32]:
            for i in range(0, len(argv), 2):
                abt_data[int(i/2)] = int(argv[i:(i+2)], 16)
            abt_data[4] = abt_data[0] ^ abt_data[1] ^ abt_data[2] ^ abt_data[3]
        else:
            print('%s is not supported option.' % argv)
            usage(sys.argv[0])
            exit(-1)
    set_uid(format, recovery, lock)


def set_uid(format = False, recovery = False, lock = False):
    # Create an object of the class MFRC522
    port = auto_find_port()
    mf_reader = MFRC522.MFRC522(dev=port)

    # Welcome message
    print_hex("MFRC522(%s) opened, will change UID to " % port, abt_data[:4])

    if recovery or anticol(mf_reader)[0]:
        # Stop encrypted traffic so we can send raw bytes
        mf_reader.MFRC522_HaltA()
        
        if mf_reader.MFRC522_OpenUidBackdoor():
            print("Card unlocked!")
            mf_reader.MFRC522_Write(0, abt_data)
            print("New Sector[00]\t%s" % (' '.join([('%02x' % x) for x in abt_data])))

            if format:
                for i in range(3, 64, 4):
                    print('Format Sector[%02d]' % i)
                    mf_reader.MFRC522_Write(i, abt_blank)

            # Make sure to stop reading for cards
            mf_reader.MFRC522_HaltA()

            if lock:
                print('Warning: Locking card will make card no longer able to modify UID!')
                mf_reader.MFRC522_LockUidSector()

                # Halt again.
                mf_reader.MFRC522_HaltA()
    else:
        print('Error: No tag available')
        exit(-2)

if __name__ == '__main__':
    main()
