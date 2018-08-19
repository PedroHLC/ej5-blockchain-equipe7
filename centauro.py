from flask import Flask, jsonify
import requests
from Crypto.Cipher import AES

app = Flask(__name__)
chain = 'http://miner.localhost:5000'
me_domain = 'centauro.com.br'
me_db = 'centauro.db'

@app.route('/')
def showmewhatyougot():
    f = open(me_db, 'r+')
    content = f.read()
    f.close()
    return content

@app.route('/wanted')
def whatyouneed():
    return jsonify(["cpf"]);

@app.route('/auth/<string:uuid>/<string:key>', methods=['GET'])
def add_user(uuid, key):
    perm = requests.get(chain+'/chain/permission', params={'uuid':uuid, 'label': me_domain})
    if(perm.status_code != 200 or perm.text != "allow"):
        return "No permission to read!"
    enc_data = requests.get(chain+'/chain/search', params={'uuid':uuid, 'type':'input', 'label':'cpf'}).text;
    aes = AES.new(key, AES.MODE_CFB, IV)
    data = aes.decrypt(enc_data)
    f = open(me_db, 'a+')
    f.write(uuid+':'+data+'\n')
    f.close()
    return ""

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    parser.add_argument('-h', '--host', default='chain.'+me_domain, type=str, help='host to listen on')
    args = parser.parse_args()

    app.run(host=args.host, port=args.port)
