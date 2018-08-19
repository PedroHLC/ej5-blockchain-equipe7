import binascii
import hashlib
import json
from collections import OrderedDict
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS

MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 1
MINING_DIFFICULTY = 2
MOTHER_ADDRESS = ''
UUID_address = 'http://mother.localhost:7000'


class Blockchain:

    def __init__(self):
        
        self.transactions = []
        self.chain = []
        self.nodes = set()
        #Generate random number to be used as node_id
        self.node_id = str(uuid4()).replace('-', '')
        #Create genesis block
        self.create_block(0, '00')


    def register_node(self, node_url):
        """
        Add a new node to the list of nodes
        """
        #Checking node_url has valid format
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    def verify_transaction_signature(self, uuid, signature, transaction):
        """
        Check that the provided signature corresponds to transaction
        signed by the public key (uuid)
        """
        # TODO: Ver se a assinatura existe no banco MOTHER
        # /get MULA
        response = requests.get(UUID_address + '/get/' +uuid , {})
        if not response:
            return False
        public_key = RSA.importKey(binascii.unhexlify(response.text))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(transaction).encode('utf8'))
        return verifier.verify(h, binascii.unhexlify(signature))


    def submit_transaction(self, uuid, type, label, value, signature):
        """
        Add a transaction to transactions array if the signature verified
        """

        # value é um JSON com informações que o sender quem compartilhar
        # Type: allow, disallow, input, sign, notify
        transaction = OrderedDict({'uuid': uuid,
                                    'type': type,
                                    'label':label,
                                    'value': value
                                    })


        # TODO: Checar se a assinatura existe no banco de dados (Se foi criada pela MOTHER)
        transaction_verification = self.verify_transaction_signature(uuid, signature, transaction)
        if transaction_verification:
            self.transactions.append(transaction)
            return len(self.chain) + 1
        else:
            return False


    def create_block(self, nonce, previous_hash):
        """
        Add a block of transactions to the blockchain
        """
        block = {'block_number': len(self.chain) + 1,
                'timestamp': time(),
                'transactions': self.transactions,
                'nonce': nonce,
                'previous_hash': previous_hash}

        # Reset the current list of transactions
        self.transactions = []
        # Our chain is bigger
        self.chain.append(block)

        return block


    def hash(self, block):
        """
        Create a SHA-256 hash of a block
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        
        return hashlib.sha256(block_string).hexdigest()


    def proof_of_work(self):
        """
        Proof of work algorithm
        """
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)

        nonce = 0
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1

        return nonce


    def valid_proof(self, transactions, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        """
        Check if a hash value satisfies the mining conditions. This function is used within the proof_of_work function.
        """
        guess = (str(transactions)+str(last_hash)+str(nonce)).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0'*difficulty


    def valid_chain(self, chain):
        """
        check if a bockchain is valid
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]

            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            # Delete the reward transaction
            transactions = block['transactions'][::]
            # Need to make sure that the dictionary is ordered. Otherwise we'll get a different hash
            transaction_elements = ['uuid', 'type', 'label','value']
            transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in transactions]

            if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        Resolve conflicts between blockchain's nodes
        by replacing our chain with the longest one in the network.
        """
        neighbours = self.nodes
        new_chain = None
        print("Nodes:"+str(neighbours))

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            print('http://' + node + '/chain')
            response = requests.get('http://' + node + '/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

# Instantiate the Node
app = Flask(__name__)
CORS(app)

# Instantiate the Blockchain
blockchain = Blockchain()

@app.route('/')
def index():
    return render_template('./index.html')

@app.route('/configure')
def configure():
    return render_template('./configure.html')


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.form
    # Check that the required fields are in the POST'ed value
    required = ['uuid', 'type', 'label', 'value', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400
    # Create a new Transaction
    #  uuid, type, label, value, signature
    transaction_result = blockchain.submit_transaction(values['uuid'],
                                                       values['type'],
                                                       values['label'],
                                                       values['value'],
                                                       request.form['signature'])

    if transaction_result == False:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to Block '+ str(transaction_result)}
        return jsonify(response), 200



@app.route('/transactions/new', methods=['GET'])
def new_transaction_get():
    uuid = request.args.get('uuid')
    tipe = request.args.get('type')
    label = request.args.get('label')
    value = request.args.get('value')
    signature = request.args.get('signature')


    transaction_result = blockchain.submit_transaction(uuid,
                                                       tipe,
                                                       label,
                                                       value,
                                                       signature)

    if transaction_result == False:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to Block '+ str(transaction_result)}
        return jsonify(response), 200


@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    #Get transactions from transactions pool
    transactions = blockchain.transactions

    response = {'transactions': transactions}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.chain[-1]
    nonce = blockchain.proof_of_work()

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)

    response = {
        'message': "New Block Forged",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    for node in blockchain.nodes:
        r = requests.get('http://' + node +'/nodes/resolve', {})
        print("\n"+node+" "+str(r.status_code))

    return jsonify(response), 200



@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form
    nodes = values.get('nodes').replace(" ", "").split(',')

    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        response = requests.get('http://'+request.form['nodes'], {})
        if response.status_code == 200:
            blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': [node for node in blockchain.nodes],
    }
    return jsonify(response), 200


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


def search_blocks_by_timestamp(chain,timestamp_low,timestamp_upp):
    blocks_list = []
    # TODO: I think it can be faster
    for block in chain:
        if (block['timestamp'] >= timestamp_low and block['timestamp'] <= timestamp_upp):
            blocks_list.append(block)

    # TODO: Can be faster
    return blocks_list


@app.route('/chain/permission',methods=['GET'])
def search_permission():
    uuid = request.args.get('uuid')
    label = request.args.get('label')

    for block in blockchain.chain[::-1]:
        for transaction in block['transactions']:
            if transaction['uuid'] == uuid and transaction['label'] == label:
                return jsonify({"type":transaction['type']}), 200

    return jsonify({'message':'Not found'}), 404


@app.route('/chain/transaction-all',methods=['GET'])
def list_all_transactions():
    uuid = request.args.get('uuid')

    list_permission = []
    for block in blockchain.chain[::-1]:
        for transaction in block['transactions']:
            if transaction['uuid'] == uuid:
                list_permission.append(transaction)

    return jsonify({"transaction": list_permission}), 200


@app.route('/chain/permission-all',methods=['GET'])
def list_permission():
    uuid = request.args.get('uuid')
    typo = request.args.get('type')
    list_permission = []
    for block in blockchain.chain[::-1]:
        for transaction in block['transactions']:
            if transaction['uuid'] == uuid and transaction['type'] == typo:
                if not transaction['label'] in list_permission:
                    list_permission.append(transaction['label'])

    return jsonify({"permissions": list_permission}), 200



# Busca por: Label, Type(3 types diferentes), Sender, timestamp
@app.route('/chain/search',methods=['GET'])
def search():
    filter = blockchain.chain

    if request.args.get('timestamp_upp') and request.args.get('timestamp_low'):
        timestamp_low = request.args.get('timestamp_low')
        timestamp_upp = request.args.get('timestamp_upp')
        filter = search_blocks_by_timestamp(filter,timestamp_low,timestamp_upp)

    # Type: Allow, Disallow, Input, Sign
    if request.args.get('type'):
        aux =[]
        for block in filter:
            block_cpp = {attr:value for attr, value in block.items()}
            block_cpp['transactions'] = []
            for transaction in block['transactions']:
                if transaction['type'] == request.args.get('type'):
                    block_cpp['transactions'].append(transaction)
            aux.append(block_cpp)
        # Filtered by type
        filter = aux[::]


    if request.args.get('label'):
        aux = []
        for block in filter:
            block_cpp = {attr: value for attr, value in block.items()}
            block_cpp['transactions'] = []
            for transaction in block['transactions']:
                if transaction['label'] == request.args.get('label'):
                    block_cpp['transactions'].append(transaction)
            aux.append(block_cpp)
        # Filtered by type
        filter = aux[::]


    if request.args.get('value'):
        aux = []
        for block in filter:
            block_cpp = {attr: value for attr, value in block.items()}
            block_cpp['transactions'] = []
            for transaction in block['transactions']:
                if transaction['value'] == request.args.get('value'):
                    block_cpp['transactions'].append(transaction)
            aux.append(block_cpp)
        # Filtered by type
        filter = aux[::]

    response = []
    for block in filter:
        for transaction in block['transactions']:
            response.append(transaction)
    return jsonify(response)


"""def generate_random_transactions(size):
    type = ['allow', 'disallow', 'input', 'sign', 'notify']
    label = ['cpf','cnh','passaporte','endereco','email.primary','phone.home','phone.work','lojinha.com.br']
    for x in range(0,size):
        random_gen = Crypto.Random.new().read
        private_key = RSA.generate(1024, random_gen)
        transaction = OrderedDict({'uuid': private_key.publickey(),
                                   'type': random.choice(type),
                                   'label': random.choice(label),
                                   'value': token_urlsafe(256)
                                   })
        blockchain.transactions.append(transaction)
"""


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('-a', '--address', default="127.0.0.1", type=str, help='ip address')
    args = parser.parse_args()
    port = args.port    
    addr = args.address
    app.run(host=addr, port=port)

