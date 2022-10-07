from gmpy2 import mpz, mpz_random, random_state
from fastecdsa import keys, curve, point
from hashlib import sha256
from os import makedirs, urandom
from sys import stderr
from math import ceil
import json
import p2p
import re
import time
import merkle
from itertools import combinations, islice

def restricted_float(x):
    try:
        x = float(x)
    except ValueError:
        raise argparse.ArgumentTypeError("%r not a floating-point literal" % (x,))

    if x <= 0.0 or x > 1.0:
        raise argparse.ArgumentTypeError("%r not in range (0.0, 1.0]"%(x,))
    return x

def json_to_point(p):
    return point.Point(int(p['x']), int(p['y']), curve.secp256k1)

def point_to_json(p):
    return({ 'x': p.x, 'y': p.y })

# unique lexicographic merge sort of public keys
def sortpoints(pks):
    if len(pks) > 1:
        mid = len(pks)//2
        left = pks[:mid]
        right = pks[mid:]

        sortpoints(left)
        sortpoints(right)

        i, j, k = 0, 0, 0

        while i < len(left) and j < len(right):
            if comparepoints(left[i], right[j]) == 1:
                pks[k] = left[i]
                i += 1
            else:
                pks[k] = right[j]
                j += 1
            k += 1

        while i < len(left):
            pks[k] = left[i]
            i += 1
            k += 1

        while j < len(right):
            pks[k] = right[j]
            j += 1
            k += 1

def comparepoints(p1, p2):
    if p1.x > p2.x:
        return 0

    elif p2.x > p1.x:
        return 1

    elif p1.y > p2.y:
        return 0

    elif p2.y > p1.y:
        return 1

    else:
        return 2

def keygen():
    priv_key, pub_key = keys.gen_keypair(curve.secp256k1)
    ## peer identifier is a str with the last 16 characters from a xor of the public key components
    peer_id = str(pub_key.x ^ pub_key.y)[-16:]

    print('Generating secp256k1 key for peer id ' + peer_id + ' in ./mykey directory...')

    makedirs('./mykey', exist_ok=True)
    keys.export_key(priv_key, curve.secp256k1, './mykey/private_key' + peer_id + '.pem')

    local_peer = {
        peer_id: {
            'ip': '127.0.0.1',
            'port': 5000,
            'public_key': {
                'x': str(pub_key.x),
                'y': str(pub_key.y)
            }
        }
    }

    print('Insert a peer entry in your configuration file using the following template (change IP and port):')
    print(json.dumps(local_peer, indent=2))

    exit(0)

def testgen(n):
    print('Generating config example in ./test directory...')
    peers = {}

    makedirs('./test', exist_ok=True)
    for i in range(0, n):
        priv_key, pub_key = keys.gen_keypair(curve.secp256k1)
        # peer identifier is a str with the last 16 characters from a xor of the public key components
        peer_id = str(pub_key.x ^ pub_key.y)[-16:]

        keys.export_key(priv_key, curve.secp256k1, 'test/' + peer_id)

        peer = {
            'ip': '127.0.0.1',
            'port': 5001 + i,
            'public_key': {
                'x': str(pub_key.x),
                'y': str(pub_key.y)
            }
        }

        peers[peer_id] = peer

    with open('test/peers', 'w', encoding='utf-8') as f:
        json.dump(peers, f, ensure_ascii=False, indent=2)

    exit(0)

class Musig:
    def __init__(self, config, priv_key_file=None, quorumpercentage=1.0):
        # Local peer id is defined by
        # 1. -c: verify if exactly one peer has a private key in the config file, this one will be the local peer
        # 2. -k: use peer identifier in private key file
        self.priv_key = 0
        self.peer_id = 0
        self.aggrX = 0
        self.quorumpercentage = float(quorumpercentage)

        f = open(config)
        self.peers = json.load(f)

        for peer in self.peers.keys():
            try:
                int(peer,10)
            except:
                stderr.write('Invalid peer identifier ' + peer + ' in config file (not decimal)')
                exit(-1)

            if len(peer) != 16:
                stderr.write('Invalid peer identifier ' + peer + ' in config file (must have 16 decimal digits)')
                exit(-1)

            if peer != str(int(self.peers[peer]['public_key']['x']) ^ int(self.peers[peer]['public_key']['y']) )[-16:]:
                stderr.write('Invalid peer identifier ' + peer + ' in config file (cannot be built from public key)')

            try:
                json_to_point(self.peers[peer]['public_key'])
            except:
                stderr.write('Invalid point for peer ' + peer + ' in config file')
                exit(-1)

            if 'private_key' in self.peers[peer].keys():
                if self.peer_id != 0:
                    stderr.write('Error: more than one peer with private key in the configuration file')
                    exit(-1)
                else:
                    try:
                        int(self.peers[peer]['private_key'])
                    except:
                        stderr.write('Invalid private key in config file (not decimal)')
                    else:
                        stderr.write('Private key ' + self.peers[peer]['private_key'] + ' found for peer ' + peer)
                        self.peer_id = self.peers[peer]
                        self.priv_key = self.peers[peer]['private_key']

            import ipaddress
            try:
                ipaddress.IPv4Address(self.peers[peer]['ip'])
            except:
                stderr.write('Invalid ip address for peer ' + peer)
                exit(-1)
            if not (self.peers[peer]['port'] in range(1024, 65535)):
                stderr.write('Invalid tcp port for peer ' + peer)
                exit(-1)

        # private key in separate pem file
        if self.priv_key == 0:
            if priv_key_file == None:
                stderr.write('Private key was not found')
                exit(-1)

            self.priv_key, self.pub_key = keys.import_key(priv_key_file)

            self.peer_id = str(self.pub_key.x ^ self.pub_key.y)[-16:]
            if not(self.peer_id in self.peers):
                stderr.write('Local peer ' + self.peer_id + ' not found in peer list')
                exit(-1)

            if self.pub_key != json_to_point(self.peers[self.peer_id]['public_key']):
                stderr.write('Local peer ' + self.peer_id + ' private key does not correspond public key found in peer list')
                exit(-1)

        if json_to_point(self.peers[self.peer_id]['public_key']) != keys.get_public_key(int(self.priv_key), curve.secp256k1):
            stderr.write('Invalid keys from peer' + peer_id + ' in config file (cannot derive public key from private key')
            exit(-1)

        self.calculate_aggr_keys()

    # recalculate the aggregated keys and merkle tree with the current membership and m-of-n configuration
    def calculate_aggr_keys(self):
        # define m-of-n values using self.quorumpercentage percentual
        self.n = len(self.peers.keys())
        self.m = ceil(float(self.quorumpercentage) * self.n)

        # ordered public keys
        pks = []
        for peer in self.peers.keys():
            pks.append(json_to_point(self.peers[peer]['public_key']))
        sortpoints(pks)

        # L
        l = sha256()
        l.update(str(pks).encode())
        self.unique_l = str(l.hexdigest())

        # create all combinations of aggregated keys for m-of-n configuration
        # if m == n, then aggr_keys[0] will be the unique aggregated key
        aggr_keys = []
        for k in range(self.m, self.n + 1):
            comb_set = combinations(pks, k)
            for subset in comb_set:
                if len(subset) == 1:
                    continue
                else:
                    aggrX, this_a_i = self.calculate_aggr_key(subset)
                    aggr_keys.append(aggrX)

        self.merkle_tree = []
        if self.quorumpercentage < 1.0 and self.n > 2:
            hash_list = merkle.threaded_hashes(aggr_keys)
            merkle.sort_hashes(hash_list)
            hash_list = merkle.clear_hash_list(hash_list)
            merkle.adjust_leafs_for_binary_tree(hash_list)
            merkle.build_tree(hash_list, self.merkle_tree)
        elif len(aggr_keys) == 1:
            self.aggr_key = aggr_keys[0]

    def join(self, peer):
        # TODO: recalculate m-of-n Merkle tree
        print('join not implemented')

    def leave(self, peer):
        # TODO: recalculate m-of-n Merkle tree
        print('leave not implemented')

    def calculate_aggr_key(self, pks):
        a = []
        this_a_i = 0
        for i in range(len(pks)):
            a_i = sha256()
            a_i.update((self.unique_l + str(pks[i])).encode())
            a_i = a_i.digest()
            a_i = int.from_bytes(a_i, byteorder='little')
            a_i = a_i % curve.secp256k1.q
            if pks[i] == json_to_point(self.peers[self.peer_id]['public_key']):
                this_a_i = a_i
            a.append(a_i)

        aggrX = pks[0] * a[0]
        for i in range(1, len(a)):
            aggrX += pks[i] * a[i]
        return aggrX, this_a_i

    # get public keys list from a peers json formatted list
    def get_pks_from_peers(self, peers):
        pks = []
        for peer in peers.keys():
            pks.append(json_to_point(peers[peer]['public_key']))
        return pks

    def sign(self, msg, signers=None):

        if signers is None:
            signers = self.peers

        if len(signers) < 2:
            stderr.write('Number of signers < 2')
            return(-1)

        aggrX, this_a_i = self.calculate_aggr_key(self.get_pks_from_peers(signers)) # this_a_i used to calculate s

        # random rlocal
        rlocal = 0
        while rlocal == 0:
            rlocal = mpz_random(random_state(int.from_bytes(urandom(4), byteorder='little')), curve.secp256k1.q)
            rlocal = int(rlocal) % curve.secp256k1.q

        # Rlocal
        Rlocal = rlocal * curve.secp256k1.G

        # ti
        ti = sha256()
        ti.update((str(Rlocal)).encode())
        ti = ti.hexdigest()

        p2p.run(signers, self.peer_id)

        pars = p2p.exchange('ti', str(ti))

        pars = p2p.exchange('Ri', point_to_json(Rlocal))

        # verify Ri
        for peer in signers.keys():
            if peer != self.peer_id:
                ti = sha256()
                Ri = json_to_point(pars[peer]['Ri'])
                ti.update((str(Ri)).encode())
                ti = ti.hexdigest()
                if ti != pars[peer]['ti']:
                    stderr.write("Error in commitment variable ti for Ri: " + ti)
                    return(-1)

        # R
        R = Rlocal
        for peer in signers.keys():
            if peer != self.peer_id:
                R += json_to_point(pars[peer]['Ri'])

        # c
        c = sha256()
        c.update((str(R) + str(aggrX) + msg).encode())
        c = c.hexdigest()
        c = int(c, 16)
        c = c % curve.secp256k1.q

        s = (mpz(rlocal) + mpz(c) * mpz(this_a_i) * mpz(self.priv_key)) % curve.secp256k1.q
        pars = p2p.exchange('si', str(s))
        p2p.stop()

        s_list = []
        for peer in signers.keys():
            if peer != self.peer_id:
                s_list.append(mpz(pars[peer]['si']))

        for si in s_list:
            s += si

        if len(self.merkle_tree) > 0:
            proof = merkle.produce_proof(aggrX, self.merkle_tree)
        else:
            proof = None

        return R, s % curve.secp256k1.q, aggrX, proof

    def verify(self, msg, R, s, aggrX=None, proof=None):
        if aggrX is None or proof is None:
            aggrX = self.aggr_key
            proof = None
        elif not merkle.verify(self.merkle_tree[0], aggrX, proof):
            return -1

        if (R is None) or (s is None) or (msg is None) or (aggrX is None):
            stderr.write('Missing parameters')
            return False

        c = sha256()
        c.update((str(R) + str(aggrX) + msg).encode())
        c = c.hexdigest()

        c = int(c, 16)

        c = c % curve.secp256k1.q

        # checking if sP = R + sum(ai*c*Xi) = R + c*X'
        left = int(s) * curve.secp256k1.G
        right = R + c * aggrX

        if left.x == right.x and left.y == right.y:
            return True
        else:
            return False

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='MuSig m-of-n signer/verifier')
    parser.add_argument('-c', '--config', help="Configuration file with peer's public keys and IPs", default='test/peers')
    parser.add_argument('-s', '--signers', help="Signers peer's list", default='test/signers') # TODO: unused yet
    parser.add_argument('-t', '--testgen', type=int, choices=range(2,16), help="Generate test configuration file")
    parser.add_argument('-g', '--keygen', action='store_true', help="Generate public key")
    parser.add_argument('-q', '--quorumpercentage', type=restricted_float, help="Percentual m/n for co-signers (0.0 - 1.0]", default = '1.0')
    parser.add_argument('-k', '--privkey', help="Private key file path", default='mykey/private_key.pem')
    args = parser.parse_args()

    # produce key pair for this peer
    if args.keygen == True:
        keygen()

    # generate a configuration example
    if args.testgen != None:
        testgen(args.testgen)

    # TODO: peer join and leave methods
    musig = Musig(args.config, args.privkey, float(args.quorumpercentage))

    if musig.quorumpercentage == 1.0:
        print('No merkle tree because m = n, calculating only one aggregated key')
    elif musig.quorumpercentage < 1.0:
        print('Merkle tree of all possible aggregated public key combinations:')
        print(musig.merkle_tree)

    # create a new dict with the first musig.m peers in config file to test m-of-n signatures for test purposes
    # XXX: if musig.peer_id is not present in the dict, the script exits
    cosigners_peers = {k: musig.peers[k] for k in list(musig.peers)[:musig.m]}

    if not(musig.peer_id in cosigners_peers.keys()):
        stderr.write('This peer ID is not one of the first ' + str(musig.m) + ' from ' + str(musig.n) + ' entries in the config file ' + args.config)
        exit(-1)

    msg = 'test123'

    R, s, aggrX, proof = musig.sign(msg, cosigners_peers)

    signature = {
        'R': point_to_json(R),
        's': int(s),
        'aggrX': point_to_json(aggrX),
        'proof': proof
    }

    print('Signature:')
    print(json.dumps(signature, indent=2))


    if musig.verify(msg, R, s, aggrX, proof):
        print('Signature is valid')
    else:
        print('Signature is not valid')
