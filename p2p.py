from flask import Flask, request, jsonify
from werkzeug.serving import make_server
import requests, threading, time
import logging
from hashlib import sha256
from fastecdsa import curve, point

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

class ServerThread(threading.Thread):
    def __init__(self, app, peers):
        threading.Thread.__init__(self)
        self.srv = make_server('127.0.0.1', int(peers[peerid]['port']), app)
        self.ctx = app.app_context()
        self.ctx.push()
    def run(self):
        self.srv.serve_forever()
    def shutdown(self):
        self.srv.shutdown()

def run(peers, peer_id):
    global peerid
    global pars
    global server

    peerid = peer_id
    pars = {}
    for peer in peers.keys():
        pars[peer] = {}
    app.config['peers'] = peers

    server = ServerThread(app, peers)
    server.start()

def stop():
    global server
    server.shutdown()

# send and receive par (ti, Ri or si) to/from all other peers
def exchange(par, val):
    app.app_context()
    peers=app.config.get('peers')

    if not (par in ['ti', 'Ri', 'si']):
        raise ValueError("par should be ti, Ri or si")

    # send par to each other peer
    for peer in peers.keys():
        if peer != peerid:
            failed_post = False
            print('Sending ' + par + ' to peer ' + peer, end='', flush=True)
            while True:
                try:
                    requests.post('http://' + str(peers[peer]['ip']) + ':' + str(peers[peer]['port']) + '/musig', json={'peerid':peerid, par: val})
                    print('', flush=True)
                    break
                except:
                    if failed_post == False:
                        print('', flush=True)
                        failed_post = True
                    print('.', end='', flush=True)
                    try:
                        time.sleep(1)
                    except KeyboardInterrupt:
                        stop()
                        raise KeyboardInterrupt

    # wait until par is received from all peers
    print("Polling " + par, flush=True)
    while True:
        pending = False
        for peer in peers.keys():
            if peer != peerid:
                if not (par in pars[peer].keys()):
                    pending = True
        if pending == False:
            break
        else:
            print('.', end='', flush=True)
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                stop()
                raise KeyboardInterrupt

    print('', flush=True)

    return pars

@app.route('/musig/', methods=['GET', 'POST'])
def musig():
    app.app_context()
    peers = app.config.get('peers')
    content = request.json

    if ('peerid' in content.keys()) and (content['peerid'] != peerid):
        if 'ti' in content.keys():
            try:
                int(content['ti'], 16)
            except:
                return jsonify("error in ti")
            pars[content['peerid']]['ti'] = content['ti']
            return jsonify({'ti': str(int(content['ti'], 16))})
        elif 'Ri' in content.keys():
            if isinstance(content['Ri'], dict):
                if 'x' in content['Ri'].keys() and 'y' in content['Ri'].keys():
                    if type(content['Ri']['x']) == int and type(content['Ri']['y']) == int:
                        pars[content['peerid']]['Ri'] = content['Ri']
                        return jsonify({'Ri': [ str(content['Ri']) ]})
            return(jsonify("error in Ri"))
        elif 'si' in content.keys():
            try:
                int(content['si'], 16)
            except:
                return jsonify("error in si")
            pars[content['peerid']]['si'] = content['si']
            return jsonify({'si': str(int(content['si'], 16))})
        else:
            return jsonify('Invalid musig parameter')
    else:
        return jsonify('Unknown peerid')

