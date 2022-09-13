from gmpy2 import mpz, mpz_random, random_state
from fastecdsa import keys, curve, point
from hashlib import sha256
from os import makedirs, urandom
from sys import stderr
import json
import p2p
import re
import time

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
    def __init__(self, config, priv_key_file):
        # Local peer id is defined by
        # 1. -c: verify if exactly one peer has a private key in the config file, this one will be the local peer
        # 2. -k: use peer identifier in private key file
        self.priv_key = 0
        self.peer_id = 0

        #print('Using config file ' + config)
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

        #print('Loaded n = ' + str(len(self.peers)) + ' peers')

        # private key in separate pem file
        if self.priv_key == 0:
            self.priv_key, self.pub_key = keys.import_key(priv_key_file)

            self.peer_id = str(self.pub_key.x ^ self.pub_key.y)[-16:]
            if not(self.peer_id in self.peers):
                stderr.write('Local peer ' + self.peer_id + ' not found in peer list')
                exit(-1)

            if self.pub_key != json_to_point(self.peers[self.peer_id]['public_key']):
                stderr.write('Local peer ' + self.peer_id + ' private key does not correspond public key found in peer list')
                exit(-1)

        #else:
            #print('Private key already found in config file. Not loading private key pem file')

        if json_to_point(self.peers[self.peer_id]['public_key']) != keys.get_public_key(int(self.priv_key), curve.secp256k1):
            stderr.write('Invalid keys from peer' + peer_id + ' in config file (cannot derive public key from private key')
            exit(-1)

        p2p.run(self.peers, self.peer_id)

        # ordered public keys
        pks = []
        for peer in self.peers.keys():
            pks.append(json_to_point(self.peers[peer]['public_key']))
        sortpoints(pks)

        # L
        l = sha256()
        l.update(str(pks).encode())
        self.unique_l = str(l.hexdigest())

        # all a_i
        a = []
        self.a_i = 0
        for i in range(len(pks)):
            a_i = sha256()
            a_i.update((self.unique_l + str(pks[i])).encode())
            a_i = a_i.digest()
            a_i = int.from_bytes(a_i, byteorder='little')
            a_i = a_i % curve.secp256k1.q
            if pks[i] == json_to_point(self.peers[self.peer_id]['public_key']):
                self.a_i = a_i
            a.append(a_i)

        # aggregated public key
        aggr_X = pks[0] * a[0]
        for i in range(1, len(a)):
            aggr_X += pks[i] * a[i]
        self.aggr_X = aggr_X

    def cosigners(m):
        if m < 2 or m >= len(self.peers):
            stderr.write('The number of co-signers m must be at least 2 and less than n in m-of-n configuration')
        print('cosigners not implemented')
        # TODO: create Merkle tree for m-of-n configuration

    def join(peer):
        # TODO: recalculate m-of-n Merkle tree
        print('join not implemented')

    def leave(peer):
        # TODO: recalculate m-of-n Merkle tree
        print('leave not implemented')

    def sign(self, msg):
        # TODO: pass set of peers from peer list participating in m-of-n multi-signature
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

        pars = p2p.exchange('ti', str(ti))

        pars = p2p.exchange('Ri', point_to_json(Rlocal))

        # verify Ri
        for peer in self.peers.keys():
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
        for peer in self.peers.keys():
            if peer != self.peer_id:
                R += json_to_point(pars[peer]['Ri'])

        # c
        c = sha256()
        c.update((str(R) + str(self.aggr_X) + msg).encode())
        c = c.hexdigest()
        c = int(c, 16)
        c = c % curve.secp256k1.q

        # s
        s = (mpz(rlocal) + mpz(c) * mpz(self.a_i) * mpz(self.priv_key)) % curve.secp256k1.q
        pars = p2p.exchange('si', str(s))
        p2p.stop()

        s_list = []
        for peer in self.peers.keys():
            if peer != self.peer_id:
                s_list.append(mpz(pars[peer]['si']))

        for si in s_list:
            s += si

        return R, s % curve.secp256k1.q

    def verify(self, R, s, msg):
        if (R is None) or (s is None) or (msg is None) or (self.aggr_X is None):
            stderr.write('Missing parameters')
            return False

        c = sha256()
        c.update((str(R) + str(self.aggr_X) + msg).encode())
        c = c.hexdigest()

        c = int(c, 16)

        c = c % curve.secp256k1.q

        # checking if sP = R + sum(ai*c*Xi) = R + c*X'
        left = int(s) * curve.secp256k1.G
        right = R + c * self.aggr_X

        if left.x == right.x and left.y == right.y:
            return True
        else:
            return False

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='MuSig signer/verifier')
    parser.add_argument('-c', '--config', help="Configuration file with peer's public keys and IPs", default='test/peers')
    parser.add_argument('-t', '--testgen', type=int, choices=range(2,16), help="Generate test configuration file")
    parser.add_argument('-g', '--keygen', action='store_true', help="Generate public key")
    parser.add_argument('-m', '--co-signers', type=int, help="Number of m-of-n co-signers")
    parser.add_argument('-k', '--privkey', help="Private key file path", default='mykey/private_key.pem')
    args = parser.parse_args()

    # produce key pair for this peer
    if args.keygen == True:
        keygen()

    # generate a configuration example
    if args.testgen != None:
        testgen(args.testgen)

    # TODO: peer join and leave methods
    # TODO: parameter m for m-of-n and Merkle tree build
    musig = Musig(args.config, args.privkey)

    msg = 'test123'

    R, s = musig.sign(msg)

    signature = {
        'R': point_to_json(R),
        's': int(s)
    }

    print('Signature:')
    print(json.dumps(signature, indent=2))

    if musig.verify(R, s, msg):
        print('Signature is valid')
    else:
        print('Signature is not valid')
