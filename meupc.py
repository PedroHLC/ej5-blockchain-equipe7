from flask import Flask, jsonify
from flask_cors import CORS
import requests
import binascii
import base64
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import ARC4
from Transactions import *

app = Flask(__name__)
CORS(app)

chain = 'http://miner.localhost:5000'

@app.route('/secret/<string:label>/<string:priv_key>', methods=['GET'])
def secret_create(label, priv_key):
    private_key = RSA.importKey(binascii.unhexlify(priv_key))
    signer = PKCS1_v1_5.new(private_key)
    h = SHA.new(label.encode('utf-8'))
    secret_key = signer.sign(h)
    return str(base64.b64encode(secret_key).decode()), 200

@app.route('/perm/<int:perm>/<string:domain>/<string:uuid>/<string:priv_key>', methods=['GET'])
def permission_create(perm, domain, uuid, priv_key):
    perm = ('allow' if perm >= 1 else 'deny')
    transaction = Transaction(uuid, priv_key, perm, domain, '')
    signature = transaction.sign_transaction()
    r = requests.get(url=chain+'/transactions/new', params={'uuid':uuid,'type':perm, 'label':domain, 'value':'','signature':signature})
    return r.text, r.status_code

@app.route('/email/<string:email>/<string:uuid>/<string:priv_key>', methods=['GET'])
def set_email(email, uuid, priv_key):
    label = 'email.primary'
    private_key = RSA.importKey(binascii.unhexlify(priv_key))
    signer = PKCS1_v1_5.new(private_key)
    h = SHA.new(label.encode('utf-8'))
    secret_key = signer.sign(h)

    value = '{"email":"'+email+'"}'
    encrypted = val_encrypt(value, label, priv_key)
    type_ = 'sign'
    
    transaction = Transaction(uuid, priv_key, type_, label, encrypted)
    signature = transaction.sign_transaction()
    r = requests.get(url=chain+'/transactions/new', params={'uuid':uuid,'type':type_, 'label':label, 'value':encrypted,'signature':signature})
    return  r.text, r.status_code

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=6000, type=int, help='port to listen on')
    parser.add_argument('-h', '--host', default='chain.meupc.me', type=str, help='host to listen on')
    args = parser.parse_args()

    app.run(host=args.host, port=args.port)
