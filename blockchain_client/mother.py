from flask import Flask, jsonify
import requests
import binascii
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
import csv
import uuid
import os
import base64
from Transactions import *

app = Flask(__name__)

BLOCKCHAIN_IP = 'http://192.168.1.184:5000'
mother_prv = open('mother.prv', 'r').read()[:-1]
mother_pub = open('mother.pub', 'r').read()[:-1]

def new_person():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    return binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'), binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')

def write_values(public_key, cpf, identifier, private_key):
    with open('basedados.csv', 'r') as f: # Abre a base e procura o cpf
        reader = csv.reader(f)
        for row in reader:
            if cpf == row[0]: # Se achar, faz as trasacoes na blockchain
                value = '{"number":"'+cpf+'"}'
                encrypted = val_encrypt(value, 'cpf', private_key)
                # Faz a req pro server fazer a transacao
                transaction = Transaction(public_key, private_key, 'input', 'cpf', encrypted)
                signature = transaction.sign_transaction()
                r = requests.get(url=BLOCKCHAIN_IP + '/transactions/new', params={'uuid':public_key,'type':'input', 'label':'cpf', 'value':encrypted,'signature':signature})
                # Valida o mesmo
                sha = SHA.new(value.encode('utf-8')).hexdigest()
                transaction = Transaction(mother_pub, mother_prv, 'sign', identifier, sha)
                signature = transaction.sign_transaction()
                r = requests.get(url=BLOCKCHAIN_IP + '/transactions/new', params={'uuid':mother_pub,'type':'sign', 'label':identifier, 'value':sha,'signature':signature})


def save_public_key(public_key, identifier):
    filename = "publics/" + str(identifier) + ".key"
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w") as f:
        f.write(public_key)

@app.route("/migrate/<string:cpf>")
def store_data(cpf):
    identifier = uuid.uuid4()
    private_key, public_key = new_person() # Pega as chaves
    save_public_key(public_key, identifier)
    write_values(public_key, cpf, identifier, private_key)
    return private_key

@app.route("/get/<string:uuid>")
def get_public_key(uuid):
    filename = 'publics/' + str(uuid) + '.key'
    try:
        return f.read(), 200
    except expression as identifier:
        return 404

@app.route("/migrate_all")
def migrate_all():
    base = csv.reader(open('basedados.csv'))
    for row in base:
        response = store_data(row[0])
    return 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('-a', '--address', default="127.0.0.1", type=str, help='inser address')
    args = parser.parse_args()
    port = args.port    
    addr = args.address

    app.run(host=addr, port=port)
