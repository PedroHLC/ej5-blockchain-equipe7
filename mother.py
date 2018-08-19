from flask import Flask, jsonify
from flask_cors import CORS
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
CORS(app)

BLOCKCHAIN_IP = 'http://miner.localhost:5000'
mother_prv = open('mother.prv', 'r').read().strip()
mother_pub = open('mother.pub', 'r').read().strip()
mother_uid = 'mother'

def new_keypair():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    return binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'), binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')

def write_values(public_key, cpf, identifier, private_key):
    with open('basedados.csv', 'r') as f: # Abre a base e procura o cpf
        reader = csv.reader(f)
        for row in reader:
            if cpf == row[0]: # Se achar, faz as trasacoes na blockchain
                mother_insertvalidated('cpf', '{"number":"'+cpf+'"}', private_key, identifier)
                mother_insertvalidated('name', '{"full":"'+row[1]+'"}', private_key, identifier)
                mother_insertvalidated('home.addr', '{"street":"'+row[2]+'","neigh":"'+row[3]+'","zip":"'+row[4]+'"}', private_key, identifier)
                mother_insertvalidated('home.city', '{"city":"'+row[5]+'","uf":"'+row[6]+'"}', private_key, identifier)
                mother_insertvalidated('birth', '{"ddmmyyyy":"'+row[7]+'"}', private_key, identifier)

def mother_insertvalidated(subject, value, private_key, identifier):
    encrypted = val_encrypt(value, subject, private_key)
    # Faz a req pro server fazer a transacao
    transaction = Transaction(identifier, private_key, 'input', subject, encrypted)
    signature = transaction.sign_transaction()
    r = requests.get(url=BLOCKCHAIN_IP + '/transactions/new', params={'uuid':identifier,'type':'input', 'label':subject, 'value':encrypted,'signature':signature})
    mother_validate(value, identifier)

@app.route("/sign/<string:value>/<string:identifier>")
def mother_validate(value, identifier):
    sha = SHA.new(value.encode('utf-8')).hexdigest()
    transaction = Transaction(mother_uid, mother_prv, 'sign', identifier, sha)
    signature = transaction.sign_transaction()
    r = requests.get(url=BLOCKCHAIN_IP + '/transactions/new', params={'uuid':mother_uid,'type':'sign', 'label':identifier, 'value':sha,'signature':signature})

def save_public_key(public_key, identifier):
    filename = "publics/" + str(identifier) + ".key"
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w") as f:
        f.write(public_key)

@app.route("/migrate/<string:cpf>")
def store_data(cpf):
    identifier = str(uuid.uuid4())
    private_key, public_key = new_keypair() # Pega as chaves
    save_public_key(public_key, identifier)
    write_values(public_key, cpf, identifier, private_key)
    data= OrderedDict({'prv': private_key,
                        'pub': public_key,
                        'uid': identifier 
                      })
    return jsonify(data), 200

@app.route("/new/<string:cpf>")
def new_person(cpf):
    identifier = str(uuid.uuid4())
    private_key, public_key = new_keypair() # Pega as chaves
    save_public_key(public_key, identifier)
    mother_insertvalidated('cpf', '{"number":"'+cpf+'"}', private_key, identifier)
    data= OrderedDict({'prv': private_key,
                        'pub': public_key,
                        'uid': identifier 
                      })
    return jsonify(data), 200

@app.route("/get/<string:uuid>")
def get_public_key(uuid):
    filename = 'publics/' + str(uuid) + '.key'
    try:
        with open(filename, "r") as f:
            return f.read().strip(), 200
    except Exception as identifier:
        return 404

@app.route("/migrate_all")
def migrate_all():
    base = csv.reader(open('basedados.csv'))
    for row in base:
        response = store_data(row[0])
    return "FINISHED", 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('-a', '--address', default="127.0.0.1", type=str, help='inser address')
    args = parser.parse_args()
    port = args.port    
    addr = args.address

    app.run(host=addr, port=port)
