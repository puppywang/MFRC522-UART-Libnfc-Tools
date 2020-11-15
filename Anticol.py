#!/usr/bin/env python
# -*- coding: utf8 -*-


import MFRC522
import signal
import sys
from Common import end_read, should_read, print_hex, auto_find_port

CASCADE_BIT = 0x4
SAK_FLAG_ATS_SUPPORTED = 0x20

def main():
    # Hook the SIGINT
    signal.signal(signal.SIGINT, end_read)

    no_rats = False
    wakeup = False
    for arg in sys.argv[1:]:
        if arg == '-n':
            no_rats = True
        if arg == '-w':
            wakeup = True

    # Create an object of the class MFRC522
    port = auto_find_port()
    mf_reader = MFRC522.MFRC522(dev=port)

    # Welcome message
    print("Welcome to the MFRC522(%s) port of nfc-anticol" % port)
    print("Press Ctrl-C to stop.")

    # This loop keeps checking for chips. If one is near it will get the UID and authenticate
    while should_read():
        if anticol(mf_reader, wakeup=wakeup, no_rats=no_rats)[0]:
            # Always halt last success card.
            mf_reader.MFRC522_HaltA()

def select_card(mf_reader: MFRC522, uid, ):
    cl = 1
    # Select the scanned tag
    (status, sak) = mf_reader.MFRC522_SelectTag(uid)
    if status != mf_reader.MI_OK:
        print('SelectTag error')
        return False, None
    if sak & CASCADE_BIT:
        cl = 2
        if uid[0] != 0x88:
            print('WARNING: Cascade bit set but CT != 0x88!')

        # We have to do the anti-collision for cascade level 2
        (status, uid2) = mf_reader.MFRC522_Anticoll(1)

        # If we have the UID, continue
        if status == mf_reader.MI_OK:
            uid += uid2

            # Select tag using UID2.
            (status, sak2) = mf_reader.MFRC522_SelectTag(uid2, 1)
            if status != mf_reader.MI_OK:
                print('SelectTag2 error')
                return False, None

            sak = sak2
            if sak2 & CASCADE_BIT:
                cl = 3
                if uid2[0] != 0x88:
                    print('WARNING: Cascade bit set but CT != 0x88!')

                    # We have to do the anti-collision for cascade level 3
                    (status, uid3) = mf_reader.MFRC522_Anticoll(2)

                    if status == mf_reader.MI_OK:
                        uid += uid3

                        # Select tag using UID2.
                        (status, sak3) = mf_reader.MFRC522_SelectTag(uid3, 2)
                        if status != mf_reader.MI_OK:
                            print('SelectTag3 error')
                            return False, None

                        sak = sak3
    return True, (uid, cl, sak)                    

def anticol(mf_reader: MFRC522, print_info = True, wakeup = False, no_rats = False):
    # Scan for cards
    (status, atqa, _) = mf_reader.MFRC522_Request(mf_reader.PICC_WUPA if wakeup else mf_reader.PICC_REQA)

    if status == mf_reader.MI_OK:
        # Get the UID of the card
        (status, uid) = mf_reader.MFRC522_Anticoll()

        # If we have the UID, continue
        if status == mf_reader.MI_OK:
            (success, card_info) = select_card(mf_reader, uid)
            if not success:
                return False, None
            (uid, cl, sak) = card_info

            ats = None
            iso_ats_supported = sak & SAK_FLAG_ATS_SUPPORTED
            if not no_rats and iso_ats_supported:
                status, ats = mf_reader.MFRC522_RequestATS()
                if status != mf_reader.MI_OK:
                    print('WARNING: ATS request failed')

            if cl == 1:
                cascade_uid = uid[0:4]
            elif cl == 2:
                cascade_uid = uid[1:4] + uid[5:9]
            elif cl == 3:
                cascade_uid = uid[1:4] + uid[6:9] + uid[10:]

            if print_info:
                print('\nFound tag with')
                print_hex(' UID: ', cascade_uid)
                print('ATQA: %02x%02x\n SAK: %02x\n' % (atqa[1], atqa[0], sak))
                if ats is not None and len(ats) > 1:
                    print_hex(' ATS: ', ats)

            return True, (cascade_uid, sak, atqa, ats)
    return False, None

if __name__ == '__main__':
    main()