Torpy ![Python Versions] [![Build Status](https://travis-ci.com/torpyorg/torpy.svg?branch=master)](https://travis-ci.com/torpyorg/torpy) [![Build status](https://ci.appveyor.com/api/projects/status/14l6t8nq4tvno1pg?svg=true)](https://ci.appveyor.com/project/jbrown299/torpy) [![Coverage Status](https://coveralls.io/repos/github/torpyorg/torpy/badge.svg?branch=master)](https://coveralls.io/github/torpyorg/torpy?branch=master)
=====

A pure python Tor client implementation of the Tor protocol.
Torpy can be used to communicate with clearnet hosts or hidden services through the [Tor Network](https://torproject.org/about/overview.html).

**Features**
- No Stem or official Tor client required
- Support v2 hidden services ([v2 specification](https://gitweb.torproject.org/torspec.git/tree/rend-spec-v2.txt))
- Support *Basic* and *Stealth* authorization protocol
- Provide simple [TorHttpAdapter](https://github.com/torpyorg/torpy/blob/master/torpy/http/adapter.py) for [requests](https://requests.readthedocs.io/) library
- Provide simple urllib [tor_opener](https://github.com/torpyorg/torpy/blob/master/torpy/http/urlopener.py) for making requests without any dependencies
- Provide simple Socks5 proxy

**Donation**

If you find this project interesting, you can send some [Bitcoins](https://bitcoin.org/) to address: `16mF9TYaJKkb9eGbZ5jGuJbodTF3mYvcRF`

**Note**

This product is produced independently from the Tor® anonymity software and carries no guarantee from [The Tor Project](https://www.torproject.org/) about quality, suitability or anything else.

Console examples
-----------
There are several console utilities to test the client.

A simple HTTP/HTTPS request:
```bash
$ torpy_cli --url https://ifconfig.me --header "User-Agent" "curl/7.37.0"
Loading cached NetworkStatusDocument from TorCacheDirStorage: .local/share/torpy/network_status
Loading cached DirKeyCertificateList from TorCacheDirStorage: .local/share/torpy/dir_key_certificates
Connecting to guard node 141.98.136.79:443 (Poseidon; Tor 0.4.3.6)... (TorClient)
Sending: GET https://ifconfig.me
Creating new circuit #80000001 with 141.98.136.79:443 (Poseidon; Tor 0.4.3.6) router...
...
Building 3 hops circuit...
Extending the circuit #80000001 with 109.70.100.23:443 (kren; Tor 0.4.4.5)...
...
Extending the circuit #80000001 with 199.249.230.175:443 (Quintex86; Tor 0.4.4.5)...
...
Stream #4: creating attached to #80000001 circuit...
Stream #4: connecting to ('ifconfig.me', 443)
Stream #4: connected (remote ip '216.239.36.21')
Stream #4: closing (state = Connected)...
Stream #4: remote disconnected (reason = DONE)
Response status: 200
Stream #4: closing (state = Closed)...
Stream #4: closed already
Closing guard connections (TorClient)...
Destroy circuit #80000001
Closing guard connections (Router descriptor downloader)...
Destroy circuit #80000002
> 199.249.230.175
```

Create Socks5 proxy to relay requests via the Tor Network:
```
$ torpy_socks -p 1050 --hops 3
Loading cached NetworkStatusDocument from TorCacheDirStorage: .local/share/torpy/network_status
Connecting to guard node 89.142.75.60:9001 (spongebobness; Tor 0.3.5.8)...
Creating new circuit #80000001 with 89.142.75.60:9001 (spongebobness; Tor 0.3.5.8) router...
Building 3 hops circuit...
Extending the circuit #80000001 with 185.248.143.42:9001 (torciusv; Tor 0.3.5.8)...
Extending the circuit #80000001 with 158.174.122.199:9005 (che1; Tor 0.4.1.6)...
Start socks proxy at 127.0.0.1:1050
...
```

Torpy module also has a command-line interface:

```bash
$ python3.7 -m torpy --url https://facebookcorewwwi.onion --to-file index.html
Loading cached NetworkStatusDocument from TorCacheDirStorage: .local/share/torpy/network_status
Connecting to guard node 185.2.31.8:443 (cx10TorServer; Tor 0.4.0.5)...
Sending: GET https://facebookcorewwwi.onion
Creating new circuit #80000001 with 185.2.31.8:443 (cx10TorServer; Tor 0.4.0.5) router...
Building 3 hops circuit...
Extending the circuit #80000001 with 144.172.71.110:8447 (TonyBamanaboni; Tor 0.4.1.5)...
Extending the circuit #80000001 with 179.43.134.154:9001 (father; Tor 0.4.0.5)...
Creating stream #1 attached to #80000001 circuit...
Stream #1: connecting to ('facebookcorewwwi.onion', 443)
Extending #80000001 circuit for hidden service facebookcorewwwi.onion...
Rendezvous established (CellRelayRendezvousEstablished())
Iterate over responsible dirs of the hidden service
Iterate over introduction points of the hidden service
Create circuit for hsdir
Creating new circuit #80000002 with 185.2.31.8:443 (cx10TorServer; Tor 0.4.0.5) router...
Building 0 hops circuit...
Extending the circuit #80000002 with 132.248.241.5:9001 (toritounam; Tor 0.3.5.8)...
Creating stream #2 attached to #80000002 circuit...
Stream #2: connecting to hsdir
Stream #2: closing...
Destroy circuit #80000002
Creating new circuit #80000003 with 185.2.31.8:443 (cx10TorServer; Tor 0.4.0.5) router...
Building 0 hops circuit...
Extending the circuit #80000003 with 88.198.17.248:8443 (bauruine31; Tor 0.4.1.5)...
Introduced (CellRelayIntroduceAck())
Destroy circuit #80000003
Creating stream #3 attached to #80000001 circuit...
Stream #3: connecting to ('www.facebookcorewwwi.onion', 443)
Extending #80000001 circuit for hidden service facebookcorewwwi.onion...
Response status: 200
Writing to file index.html
Stream #1: closing...
Stream #3: closing...
Closing guard connections...
Destroy circuit #80000001
```

Usage examples 
-----------

A basic example of how to send some data to a clearnet host or a hidden service:
```python
from torpy import TorClient

hostname = 'ifconfig.me'  # It's possible use onion hostname here as well
with TorClient() as tor:
    # Choose random guard node and create 3-hops circuit
    with tor.create_circuit(3) as circuit:
        # Create tor stream to host
        with circuit.create_stream((hostname, 80)) as stream:
            # Now we can communicate with host
            stream.send(b'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' % hostname.encode())
            recv = stream.recv(1024)
```

TorHttpAdapter is a convenient Tor adapter for the [requests library](https://2.python-requests.org/en/master/user/advanced/#transport-adapters).
The following example shows the usage of TorHttpAdapter for multi-threaded HTTP requests:
```python
from multiprocessing.pool import ThreadPool
from torpy.http.requests import tor_requests_session

with tor_requests_session() as s:  # returns requests.Session() object
    links = ['http://nzxj65x32vh2fkhk.onion', 'http://facebookcorewwwi.onion'] * 2

    with ThreadPool(3) as pool:
        pool.map(s.get, links)

```

For more examples see [test_integration.py](https://github.com/torpyorg/torpy/blob/master/tests/integration/test_integration.py)


Installation
------------
* Just `pip3 install torpy`
* Or for using TorHttpAdapter with requests library you need install extras:
`pip3 install torpy[requests]`

Contribute
----------
* Use It
* Code review is appreciated
* Open [Issue], send [PR]


TODO
----
- [ ] Implement v3 hidden services [specification](https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt)
- [ ] Refactor Tor cells serialization/deserialization
- [ ] More unit tests
- [ ] Rewrite the library using asyncio
- [ ] Implement onion services


License
-------
Licensed under the Apache License, Version 2.0


References
----------
- Official [Tor](https://gitweb.torproject.org/tor.git/) client
- [Pycepa](https://github.com/pycepa/pycepa)
- [TorPylle](https://github.com/cea-sec/TorPylle)
- [TinyTor](https://github.com/Marten4n6/TinyTor)
- C++ Windows only implementation [Mini-tor](https://github.com/wbenny/mini-tor)
- Nice Java implementation [Orchid](https://github.com/subgraph/Orchid)


[Python Versions]:      https://img.shields.io/badge/python-3.6,%203.7,%203.8,%203.9-blue.svg
[Issue]:                https://github.com/torpyorg/torpy/issues
[PR]:                   https://github.com/torpyorg/torpy/pulls