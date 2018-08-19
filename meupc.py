from flask import Flask, jsonify
import requests
import binascii
import base64
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import ARC4

app = Flask(__name__)
chain = 'http://miner.localhost:5000'

@app.route('/secret/create/<string:label>/<string:priv_key>', methods=['GET'])
def secret_create(label, priv_key):
    private_key = RSA.importKey(binascii.unhexlify(priv_key))
    signer = PKCS1_v1_5.new(private_key)
    h = SHA.new(label.encode('utf-8'))
    secret_key = signer.sign(h)
    return str(base64.b64encode(secret_key).decode()), 200

@app.route('/perm/create/<int:perm>/<string:domain>/<string:uuid>/<string:priv_key>', methods=['GET'])
def permission_create(perm, domain, uuid, priv_key):
    return 404

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=6000, type=int, help='port to listen on')
    parser.add_argument('-h', '--host', default='chain.meupc.me', type=str, help='host to listen on')
    args = parser.parse_args()

    app.run(host=args.host, port=args.port)
