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
        return OrderedDict({'uuid': self.uuid,
                            'type': self.type,
                            'label': self.label,
                            'value': val_encrypt(self.value, self.label, self.sender_private_key)
                            })

    def sign_transaction(self):
        """
		Sign transaction with private key
		"""
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')


app = Flask(__name__)


@app.route('/')
def index():
    return render_template('./examples.html')


@app.route('/make/transaction')
def make_transaction():
    return render_template('./make_transaction.html')


@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')


@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    response = {
        'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
        'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
    }

    return jsonify(response), 200


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    uuid = request.form['uuid']
    sender_private_key = request.form['sender_private_key']
    type = request.form['type']
    label = request.form['label']
    value = request.form['value']
    transaction = Transaction(uuid, sender_private_key, type, label, value)

    response = {'transaction': transaction.to_dict(), 'signature': transaction.sign_transaction()}

    # print("\n"+str(response)+"\n")
    return jsonify(response), 200

def val_encrypt(value, label, sender_private_key):
    private_key = RSA.importKey(binascii.unhexlify(sender_private_key))
    signer = PKCS1_v1_5.new(private_key)
    h = SHA.new(label.encode('utf8'))
    secret_key = signer.sign(h)
    cipher = ARC4.new(secret_key)
    encoded = cipher.encrypt(value)
    return str(base64.b64encode(encoded).decode())

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-a', '--address', default='127.0.0.1', type=str, help='host to listen on')
    parser.add_argument('-p', '--port', default=8090, type=int, help='port to listen on')
    args = parser.parse_args()
    host = args.address
    port = args.port

    app.run(host=host, port=port)
