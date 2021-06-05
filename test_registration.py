#!/usr/bin/env python3

from registration import *

# content of test_sample.py
def func(x):
    return x + 2

def test_answer():
    assert func(3) == 5

def test_pad_for_sha256():
    assert pad_for_sha256(b's.walchshaeusl@tum.de\r\nSebastian\r\nWalchshaeusl\r\nga84mi') == True
    # assert pad_for_sha256(b'a') == b'01'

def test_get_info_message():
    assert get_info_message() == b's.walchshaeusl@tum.de\r\nSebastian\r\nWalchshaeusl\r\nga84mim'