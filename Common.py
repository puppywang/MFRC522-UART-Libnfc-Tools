#!/usr/bin/env python
# -*- coding: utf8 -*-

from serial.tools import list_ports

continue_reading = True

def print_hex(prompt, data, end=None):
    print(prompt + ' '.join(['%02x' % x for x in data]), end=end)

def end_read(signal, frame):
    global continue_reading
    print("Ctrl+C captured, exit...")
    continue_reading = False
    exit()

def should_read():
    return continue_reading

def auto_find_port():
    valid_ports = list(list_ports.grep('USB-SERIAL'))
    if len(valid_ports) > 0:
        return valid_ports[0].device
    print('No valid COM port found!')
    exit(-10)