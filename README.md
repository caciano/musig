# musig
This is a python implementation of [MuSig](https://eprint.iacr.org/2018/068.pdf) multi-signature scheme. It uses `secp256k1` elliptic curve from fastecdsa library and Flask REST API for peers' 3-round communication protocol.

The library uses a json configuration file to load peers' public keys and connection information (IPs and ports) as the example below:
```json
{
  "1171431706335400": {
    "ip": "127.0.0.1",
    "port": 5001,
    "public_key": {
      "x": "99930830503112209261592169493434240409039586552388298840179708253245074360017",
      "y": "5034899717072795466923690703431603456214882247405347141139963223839930965625"
    }
  },
  "9453413367952217": {
    "ip": "127.0.0.1",
    "port": 5002,
    "public_key": {
      "x": "112024443911085041094769117829780886468361331345689728827839398871173357240798",
      "y": "48252319428854364602380679836439578177672833704419879797199311460977547031175"
    }
  },
  "2371736415565761": {
    "ip": "127.0.0.1",
    "port": 5003,
    "public_key": {
      "x": "24274641748319670125331852498382998631221179518239155158745285046386749561609",
      "y": "65168397121885410958317872754314700143002845118731826976200433535642617228488"
    }
  },
  "9328895668671339": {
    "ip": "127.0.0.1",
    "port": 5004,
    "public_key": {
      "x": "96047938843158482033656272492658724408271570723669403090641451702233876221265",
      "y": "56992848257150377623562937143360130690722348588766570691546602933679246614074"
    }
  }

```

To create an example file for 4 peers you can execute:
```
$ python3 musig.py -t 4
Generating config example in ./test directory...
```

Each peer is identified by its peer id (e.g. "1171431706335400", "9453413367952217", ...). The peer id is used to name the private keys (elliptic curve PEM files) and the entries in the peers file. All entries in the example will be configured in localhost (IP 127.0.0.1) and a different TCP port above 5000. To test the multi-signature process execute 4 instances of the following command. Each instance should receive as parameter a different private key file in the directory test using the parameter -k.
```
$ python3 musig.py -k test/1149973529359945
Sending ti to peer 7588995846541392
Sending ti to peer 3017244107571394
Sending ti to peer 6014440447135681
........................
Polling ti

Sending Ri to peer 7588995846541392
Sending Ri to peer 3017244107571394
Sending Ri to peer 6014440447135681
Polling Ri
.
Sending si to peer 7588995846541392
Sending si to peer 3017244107571394
Sending si to peer 6014440447135681
Polling si
.
Signature:
{
  "s": 85904266701813689403005095883412819476301064476154711951388008088749370209023,
  "R": {
    "x": 10878165741530584965847656936497572975279752918888888532750839039781476757814,
    "y": 99208477439296111544544474029419117238202856907155393509848382559097121519266
  }
}
Signature is valid

```

To create a private key and the configuration for your peer:
```
$ python3 musig.py -g
Generating secp256k1 key for peer id 5343039124930959 in ./mykey directory...
Insert a peer entry in your configuration file using the following template (change IP and port):
{
  "5343039124930959": {
    "ip": "127.0.0.1",
    "port": 5000,
    "public_key": {
      "x": "68879860661845177065467769440178003376740873566799564026258970471087772554000",
      "y": "106238324084122496870038779645625163514131788975344294788226759318178633110175"
    }
  }
}
```

Below is an example of how to use the library to sign and verify messages:
```python
import musig

ms = musig.Musig('peers_file', 'mykey/private_key6509695481504055.pem')

R, s = ms.sign('Message')

if ms.verify(R, s, 'Message'):
    print('Signature is valid')
else:
    print('Signature is not valid')
```

Here is an example of how to use the library using threshold (m-of-n) multisignatures:
```python
import musig

# builds peer list and all possible aggregated public keys in 3-of-4 (0.75%) scheme
# also builds the merkle tree of aggr pks to allow further multisignature verification
ms = musig.Musig('peers_file', 'mykey/private_key6509695481504055.pem', quorumpercentage=0.75)

# select the first m out of a total of n peers (3-of-4) to sign the message
cosigners_peers = {k: ms.peers[k] for k in list(ms.peers)[:ms.m]}

R, s = ms.sign('Message', cosigners_peers)

if ms.verify(R, s, 'Message'):
    print('Signature is valid')
else:
    print('Signature is not valid')
```
