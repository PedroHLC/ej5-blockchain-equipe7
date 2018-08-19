from flask import Flask, jsonify
import requests
from Crypto.Cipher import AES

app = Flask(__name__)
chain = 'http://chain.meupc.me:8080'
me_domain = 'lojinha.com.br'

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
    f = open('lojinha.db', 'a+')
    f.write(uuid+':'+data+'\n')
    f.close()

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('-h', '--host', default='chain.lojinha.com.br', type=str, help='host to listen on')
    args = parser.parse_args()

    app.run(host=args.host, port=args.port)
