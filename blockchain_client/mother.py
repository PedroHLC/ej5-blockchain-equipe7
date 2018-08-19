from flask import Flask, request
import binascii
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
import csv
import uuid
import os

app = Flask(__name__)

BLOCKCHAIN_IP = 'http://192.168.1.184:5000/'

@app.route('/wallet/new', methods=['POST'])
def new_key(cpf):
    required = ['cpf']
    if not all(k in values for k in required) or cpf:
        return 'Missing values', 400
    cpf = request['cpf']
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = cpf
    response = {
        'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
        'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
    }

    return jsonify(response), 200

def write_values(public_key, cpf, identifier):
    with open('basedados.csv', 'r') as f:               # Abre a base e procura o cpf
        reader = csv.reader(f)
        for row in reader:
            if cpf == row[0]:                           # Se achar, faz as trasacoes na blockchain
                for dado in row:
                    request.post(BLOCKCHAIN_IP + 
                    'transactions/new?sender_adress=' + public_key + 
                    '&type=input&label=''&value=' + dado + 
                    '&signature=' + identifier)  # Faz a req pro server fazer a transacao
                break

def save_public_key(public_key, identifier):
    filename = "/publics/" + public_key + ".key"
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w") as f:
        f.write(identifier)

#@app.route("/migrate")
#def init_values():
#    pass

@app.route("/migrate")
def store_data():
    required = ['cpf']
    if not all(k in values for k in required):
        return 'Missing values', 400
    cpf = request['cpf']
    identifier = uuid.uuid4()
    private_key, public_key = new_key(cpf) # Pega as chaves
    write_values(public_key, cpf, identifier)
    save_public_key(public_key, identifier)
    return private_key


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('-a', '--address', default="127.0.0.1", type=str, help='inser address')
    args = parser.parse_args()
    port = args.port    
    addr = args.address

    app.run(host=addr, port=port)