import base64
from collections import OrderedDict

import binascii

import Crypto
import Crypto.Random as vai_dormir
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import AES, ARC4

import requests
from flask import Flask, jsonify, request, render_template


class Transaction:
    #  uuid, type, label, value, signature
    def __init__(self, uuid, sender_private_key, type, label, value):
        self.uuid = uuid
        self.sender_private_key = sender_private_key
        self.type = type
        self.label = label
        self.value = value

    def to_dict(self):
        data= OrderedDict({'uuid': self.uuid,
                            'type': self.type,
                            'label': self.label,
                            'value': self.value 
                            })
        return data

    def sign_transaction(self):
        """
		Sign transaction with private key
		"""
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')

def val_encrypt(value, label, sender_private_key):
    private_key = RSA.importKey(binascii.unhexlify(sender_private_key))
    signer = PKCS1_v1_5.new(private_key)
    h = SHA.new(label.encode('utf8'))
    secret_key = signer.sign(h)
    cipher = ARC4.new(secret_key)
    encoded = cipher.encrypt(value)
    return str(base64.b64encode(encoded).decode())
