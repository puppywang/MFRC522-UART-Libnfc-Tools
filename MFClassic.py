#!/usr/bin/env python
# -*- coding: utf8 -*-


import MFRC522
import sys
import time
from Anticol import anticol, auto_find_port, print_hex

# Guess keys
GUESS_KEYS = [
    # [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],   # Default key (first key used by program if no user defined key)
    # [0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7],   # NFCForum content key
    # [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5],   # NFCForum MAD key
    # [0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5],
    # [0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd],
    # [0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a],
    # [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    # [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],   # Blank key
    # [0xab, 0xcd, 0xef, 0x12, 0x34, 0x56],
    [0xB5, 0xFF, 0x67, 0xCB, 0xA9, 0x51],
    [0x71, 0x4c, 0x5c, 0x88, 0x6e, 0x97],
    [0x58, 0x7e, 0xe5, 0xf9, 0x35, 0x0f],
    [0xa0, 0x47, 0x8c, 0xc3, 0x90, 0x91],
    [0x53, 0x3c, 0xb6, 0xc7, 0x23, 0xf6],
    [0x8f, 0xd0, 0xa4, 0xf2, 0x56, 0xe9]
]

DEFAULT_KEY = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
DEFAULT_ACL = [0xff, 0x07, 0x80, 0x69]


def usage(program_name):
    print('Usage: ')
    print(
        '%s f|r|R|w|W a|b u|U<01ab23cd> <dump.mfd> [<keys.mfd> [f]]' % program_name)
    print("  f|r|R|w|W     - Perform format (f) or read from (r) or unlocked read from (R) or write to (w) or unlocked write to (W) card")
    print("                  *** format will reset all keys to FFFFFFFFFFFF and all data to 00 and all ACLs to default")
    print("                  *** unlocked read does not require authentication and will reveal A and B keys")
    print("                  *** note that unlocked write will attempt to overwrite block 0 including UID")
    print("                  *** unlocking only works with special Mifare 1K cards (Chinese clones)")
    print("  a|A|b|B       - Use A or B keys for action; Halt on errors (a|b) or tolerate errors (A|B)")
    print("  u|U           - Use any (u) uid or supply a uid specifically as U01ab23cd.")
    print("  <dump.mfd>    - MiFare Dump (MFD) used to write (card to MFD) or (MFD to card)")
    print("  <keys.mfd>    - MiFare Dump (MFD) that contain the keys (optional)")
    print("  f             - Force using the keyfile even if UID does not match (optional)")
    print("Examples: \n")
    print("  Read card to file, using key A:\n")
    print("    %s r a u mycard.mfd\n" % program_name)
    print("  Write file to blank card, using key A:\n")
    print("    %s w a u mycard.mfd\n" % program_name)
    print("  Write new data and/or keys to previously written card, using key A:\n")
    print("    %s w a u newdata.mfd mycard.mfd\n" % program_name)
    print("  Format/wipe card (note two passes required to ensure writes for all ACL cases):\n")
    print("    %s f A u dummy.mfd keyfile.mfd f" % program_name)
    print("    %s f B u dummy.mfd keyfile.mfd f\n" % program_name)
    print("  Read card to file, using key A and uid 0x01 0xab 0x23 0xcd:\n")
    print("    %s r a U01ab23cd mycard.mfd\n" % program_name)


def main():
    if len(sys.argv) < 5:
        usage(sys.argv[0])
        exit(-1)

    command = sys.argv[1]
    action_write = False
    if command in ['r', 'R', 'ra']:
        unlock = command == 'R'
        format_card = False
        no_auth = command == 'ra'
    elif command in ['w', 'W', 'f', 'wa']:
        unlock = command = 'W'
        format_card = command == 'f'
        action_write = True
        no_auth = command = 'rw'
    else:
        usage(sys.argv[0])
        exit(-1)

    key_a = sys.argv[2] in ['a', 'A']
    allow_failure = sys.argv[2] in ['A', 'B']
    key_file = len(sys.argv) > 5
    force_key_file = len(sys.argv) > 6 and sys.argv[6] == 'f'

    if sys.argv[3][0] == 'U':
        if len(sys.argv[3]) != 9:
            print('Error, illegal tag specification, use U01ab23cd for example.')
            usage(sys.argv[0])
            exit(-1)
        tag_uid = [0] * 4
        for i in range(0, 8, 2):
            tag_uid[int(i/2)] = int(sys.argv[3][i+1:(i+3)], 16)
        print("Attempting to use specific UID: %02x %02x %02x %02x" %
              (tag_uid[0], tag_uid[1], tag_uid[2], tag_uid[3]))
    else:
        tag_uid = None

    # We don't know yet the card size so let's read only the UID from the keyfile for the moment
    key_bin = None
    if key_file:
        try:
            with open(sys.argv[5], 'rb') as key_fp:
                key_bin = key_fp.read()
                if len(key_bin) < 4:
                    print("Could not read UID from key file: %s" % sys.argv[5])
                    exit(-1)
        except IOError as err:
            print('Could not open keys file: %s, err = %s' %
                  (sys.argv[5], err))
            exit(-1)

    port = auto_find_port()
    mf_reader = MFRC522.MFRC522(dev=port)

    # Welcome message
    print("MFRC522(%s) opened." % port)

    (success, card_info) = anticol(mf_reader, no_rats=True)
    if not success:
        print('Error: no tag was found')
        exit(-1)
    (uid, sak, atqa, ats) = card_info
    if sak & 0x08 == 0:
        print('Warning: tag is probably not a MFC!')
    if key_file:
        if uid != key_bin[:4]:
            print_hex(
                "Expected MIFARE Classic card with UID starting as: ", key_bin[:4])
            print_hex(
                "Got card with UID starting as:                     ", uid)
        if not force_key_file:
            print("Aborting!")
            exit(-1)
    print_hex('Found MIFARE Classic card: ', uid)
    # Guess size.
    if atqa[1] & 0x02 == 0x02 or sak == 0x18:
        # 4K
        blocks = 0xff
    elif sak == 0x09:
        # 320b
        blocks = 0x13
    else:
        # 1K/2K, checked through RATS
        blocks = 0x3f
    # Testing RATS
    magic2 = False
    if ats != None:
        if len(ats) > 10 and ats[5:9] == [0xc1, 0x05, 0x2f, 0x2f] and (atqa[1] & 0x02 == 0):
            # MIFARE Plus 2K
            blocks = 0x7f
        elif len(ats) == 9 and ats[5:9] == [0xda, 0xbc, 0x19, 0x10]:
            #  // Chinese magic emulation card, ATS=0978009102:dabc1910
            magic2 = True
    print('Guessing size: seems to be a %lu-byte card' % ((blocks + 1) * 16))

    if key_file:
        if len(key_bin) != (blocks + 1) * 16:
            print('Could not read key file: %s, should %d vs %d' %
                  (sys.argv[5], (blocks + 1) * 16, len(key_bin)))
            exit(-1)

    dump_bin = None
    if action_write:
        try:
            with open(sys.argv[4], 'rb') as dump_fp:
                dump_bin = dump_fp.read((blocks + 1) * 16)
                if len(dump_bin) != (blocks + 1) * 16:
                    print('Could not read key file: %s, should %d vs %d' %
                          (sys.argv[4], (blocks + 1) * 16, len(dump_bin)))
                    exit(-1)
        except IOError as err:
            print('Could not open dump file: %s, err = %s' %
                  (sys.argv[4], err))
            exit(-1)

    # Begin the real work.
    if not action_write:
        (success, dump_bin) = read_card(mf_reader, uid, unlock, key_bin, magic2, blocks, key_a, allow_failure, no_auth)
        if success:
            print('Writing data to file: %s ...' % sys.argv[4], end='', flush=True)
            try:
                with open(sys.argv[4], 'wb') as dump_fp:
                    write_cnt = dump_fp.write(bytearray(dump_bin))
                    if write_cnt != (blocks + 1) * 16:
                        print('Could not write to file: %s, should %d vs %d' % (sys.argv[4], (blocks + 1) * 16, write_cnt))
                        success = False
                    else:
                        print('Done.')
            except IOError as err:
                print('Could not open dump file: %s, err = %s' % (sys.argv[4], err))
                success = False
    else:
        success = write_card(mf_reader, uid, unlock, key_bin, magic2, blocks, key_a, allow_failure, dump_bin, format_card, no_auth)

    mf_reader.MFRC522_HaltA()
    mf_reader.MFRC522_StopCrypto1()
    exit(0 if success else -1)


def is_first_block(block):
    if block < 128:
        return block % 4 == 0
    else:
        return block % 16 == 0


def is_trailer_block(block):
    if block < 128:
        return (block + 1) % 4 == 0
    else:
        return (block + 1) % 16 == 0


def get_trailer_block(block):
    if block < 128:
        return block + (3 - (block % 4))
    else:
        return block + (15 - (block % 16))


def auth_card(mf_reader: MFRC522, uid, key_bin, block, key_a, format):
    cmd = mf_reader.PICC_AUTHENT1A if key_a else mf_reader.PICC_AUTHENT1B
    if key_bin is not None:
        trailer_block = get_trailer_block(block)
        if key_a:
            key = key_bin[trailer_block * 16 : (trailer_block * 16) + 6]
        else:
            key = key_bin[(trailer_block * 16) + 10 : (trailer_block * 16) + 16]
        if mf_reader.MFRC522_Auth(cmd, block, key, uid) == mf_reader.MI_OK:
            return True, key
    if format or key_bin is None:
        for key in GUESS_KEYS:
            if mf_reader.MFRC522_Auth(cmd, block, key, uid) == mf_reader.MI_OK:
                return True, key
            # Try to anticol again.
            mf_reader.MFRC522_HaltA()
            mf_reader.antennaOff()
            time.sleep(0.1)
            mf_reader.antennaOn()
            (success, _) = anticol(mf_reader, print_info=False, wakeup=True, no_rats=True)
            if not success:
                print('tag was removed', end='')
                return False, None
    # Faild to find keys.
    return False, None


def print_success_or_failure(failure, success_blocks):
    print('%c' % 'x' if failure else '.', end='', flush=True)
    if not failure:
        success_blocks += 1
    return success_blocks


def read_card(mf_reader, uid, read_unlock, key_bin, magic2, blocks, key_a, allow_failure, no_auth):
    if read_unlock:
        if magic2:
            print('Note: This card does not require an unlocked write (R)')
            read_unlock = False
        else:
            mf_reader.MFRC522_HaltA()
            if mf_reader.MFRC522_OpenUidBackdoor():
                print("Card unlocked!")
            else:
                return False, None

    print('Reading out %d blocks |' % (blocks + 1), end='', flush=True)

    failure = False
    dump_bin = []
    success_blocks = 0
    # Read the card from end to begin
    for block in range(blocks, -1, -1):
        # Authenticate everytime we reach a trailer block
        if is_trailer_block(block):
            if failure:
                # When a failure occured we need to redo the anti-collision
                (success, _) = anticol(mf_reader, print_info=False, wakeup=True, no_rats=True)
                if not success:
                    print('!\nError: tag was removed')
                    return False, None

            if not read_unlock and not no_auth:
                (success, key) = auth_card(mf_reader, uid, key_bin, block, key_a, False)
                if not success:
                    print('!\nError: authentication failed for block 0x%02x' % block)
                    return False, None
            if no_auth:
                # Try to collect as default key.
                key = DEFAULT_KEY

            (status, data) = mf_reader.MFRC522_Read(block)
            if status == mf_reader.MI_OK:
                # We read in reverse order, so we append data in front of last data.
                if read_unlock:
                    dump_bin = data[1] + dump_bin
                elif key_bin:
                    dump_bin = (key_bin[block * 16 : (block * 16) + 6] + data[1][6:10] + key_bin[(block * 16) + 10 : (block * 16) + 16]) + dump_bin
                else:
                    dump_bin = ((key if key_a else DEFAULT_KEY) + data[1][6:10] + (DEFAULT_KEY if key_a else key)) + dump_bin
            else:
                print('!\nfailed to read trailer block 0x%02x' % block)
                failure = True
        else:
            # Make sure a earlier readout did not fail
            if not failure:
                (status, data) = mf_reader.MFRC522_Read(block)
                if status == mf_reader.MI_OK:
                    # We read in reverse order, so we append data in front of last data.
                    dump_bin = data[1] + dump_bin
                else:
                    print('!\nError: unable to read block 0x%02x' % block)
                    failure = True
        # Show if the readout went well for each block
        success_blocks = print_success_or_failure(failure, success_blocks)
        if not allow_failure and failure:
            return False, None
    print('|')
    print('Done, %d of %d blocks read.' % (success_blocks, blocks + 1))
    
    return True, dump_bin


def write_card(mf_reader, uid, write_block_zero, key_bin, magic2, blocks, key_a, allow_failure, dump_bin, format_card, no_auth):
    if write_block_zero:
        if magic2:
            print('Note: This card does not require an unlocked write (W)')
            write_block_zero = False
        else:
            mf_reader.MFRC522_HaltA()
            if mf_reader.MFRC522_OpenUidBackdoor():
                print("Card unlocked!")
            else:
                return False

    print('Writing %d blocks |' % (blocks + 1), end='', flush=True)
    for block in range(0, blocks+1):
        if is_first_block(block):
            if failure:
                (success, _) = anticol(mf_reader, print_info=False, wakeup=True, no_rats=True)
                if not success:
                    print('!\nError: tag was removed')
                    return False

            if not write_block_zero and not no_auth and not auth_card(mf_reader, uid, key_bin, block, key_a, format_card) and not allow_failure:
                print('!\nError: authentication failed for block 0x%02x' % block)
                return False

            if is_trailer_block(block):
                if format_card:
                    # Copy the default key and reset the access bits
                    trailer = DEFAULT_KEY + DEFAULT_ACL + DEFAULT_KEY
                else:
                    trailer = dump_bin[block*16 : (block+1)*16]
                # Try to write the trailer
                if mf_reader.MFRC522_Write(block, trailer) != mf_reader.MI_OK:
                    print('failed to write trailer block %d' % block, end='', flush=True)
                    failure = True
            else:
                if block == 0 and not write_block_zero and not magic2:
                    continue

                # Make sure a earlier write did not fail
                if not failure:
                    if format_card and block:
                        data = [0x00] * 16
                    else:
                        data = dump_bin[block*16 : (block+1)*16]
                    if block == 0:
                        if data[0] ^ data[1] ^ data[2] ^ data[3] ^ data[4] != 0x0 and not magic2:
                            print('!\nError: incorrect BCC in MFD file!')
                            print('Expecting BCC=%02X' % data[0] ^ data[1] ^ data[2] ^ data[3])
                            return False
                    if mf_reader.MFRC522_Write(block, data) != mf_reader.MI_OK:
                        failure = True
        # Show if the write went well for each block
        success_blocks = print_success_or_failure(failure, success_blocks)
        if not allow_failure and failure:
            return False
    print('|')
    print('Done, %d of %d blocks written.' % (success_blocks, blocks + 1))
    
    return True


if __name__ == '__main__':
    main()