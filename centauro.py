import requests
import base64
import json
from flask import Flask, jsonify
from Crypto.Cipher import ARC4

app = Flask(__name__)
chain = 'http://miner.localhost:5051'
me_domain = 'centauro.com.br'
me_db = 'centauro.db'

@app.route('/debug')
def showmewhatyougot():
    f = open(me_db, 'r+')
    content = f.read()
    f.close()
    return content

@app.route('/wanted')
def whatyouneed():
    return jsonify(["cpf"]);

@app.route('/auth')
def add_user(uuid, secret_key):
    perm = requests.get(chain+'/chain/permission', params={'uuid':uuid, 'label': me_domain})
    if(perm.status_code != 200 or (not "allow" in perm.text)):
        return "No permission to read!"
    response = requests.get(chain+'/chain/search', params={'uuid':uuid, 'type':'input', 'label':'cpf'})
    encoded = json.loads(response.text)[0]["value"]
    cipher = ARC4.new(base64.b64decode(secret_key))
    data = cipher.decrypt(base64.b64decode(encoded))
    f = open(me_db, 'a+')
    f.write(uuid+':'+data.decode()+'\n')
    f.close()
    return ""

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    parser.add_argument('-h', '--host', default='chain.'+me_domain, type=str, help='host to listen on')
    args = parser.parse_args()

    app.run(host=args.host, port=args.port)
