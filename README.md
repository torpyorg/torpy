Torpy ![Python Versions] [![Build Status](https://travis-ci.com/torpyorg/torpy.svg?branch=master)](https://travis-ci.com/torpyorg/torpy) [![Coverage Status](https://coveralls.io/repos/github/torpyorg/torpy/badge.svg?branch=master)](https://coveralls.io/github/torpyorg/torpy?branch=master)
=====

A pure-Python implementation of the Tor protocol.
Torpy can be used to communicate with clearnet hosts or hidden services through the [Tor Network](https://torproject.org/about/overview.html). 

**Features**
- No Stem or official Tor client required
- Support v2 hidden services ([v2 specification](https://gitweb.torproject.org/torspec.git/tree/rend-spec-v2.txt))
- Support *Basic* and *Stealth* authorization protocol
- Provide simple TorHttpAdapter for [requests](https://2.python-requests.org)
- Provide simple Socks5 proxy

**Note:** This product is produced independently from the Tor® anonymity software and carries no guarantee from [The Tor Project](https://www.torproject.org/) about quality, suitability or anything else.

Console examples
-----------
There are several console utilities to test the client.

A simple HTTP/HTTPS request:
```bash
$ torpy_cli --url https://ifconfig.me --header "User-Agent" "curl/7.37.0"
Downloading new consensus from gabelmoo authority
Connecting to guard node 144.217.94.84:443 (ezrin; Tor 0.3.5.8)...
Sending: GET https://ifconfig.me
Creating new circuit #80000001 with 144.217.94.84:443 (ezrin; Tor 0.3.5.8) router...
Building 3 hops circuit...
Extending the circuit #80000001 with 95.211.147.99:9001 (RNVR217; Tor 0.3.5.7)...
Extending the circuit #80000001 with 45.33.43.215:443 (a0xo; Tor 0.3.5.8)...
Creating stream #1 attached to #80000001 circuit...
Stream #1: connecting to ('ifconfig.me', 443)
Response status: 200
> 45.33.43.215
Stream #1: closing...
Closing guard connections...
Destroy circuit #80000001
```

Create Socks5 proxy to relay requests via the Tor Network:
```
$ torpy_socks -p 1050 --hops 3
Downloading new consensus from bastet authority
Connecting to guard node 45.77.80.140:9001 (sparklingengine; Tor 0.2.9.11)...
Creating new circuit #80000001 with 45.77.80.140:9001 (sparklingengine; Tor 0.2.9.11) router...
Building 3 hops circuit...
Extending the circuit #80000001 with 185.13.39.197:443 (Neldoreth; Tor 0.3.5.8)...
Extending the circuit #80000001 with 77.247.181.163:22 (amartysen; Tor 0.3.5.8)...
Start socks proxy at 127.0.0.1:1050
...
```

Torpy module also has a command-line interface:

```bash
$ python3.7 -m torpy --url https://facebookcorewwwi.onion --to-file index.html
Downloading new consensus from bastet authority
Connecting to guard node 5.9.173.35:443 (killto; Tor 0.2.9.16)...
Sending: GET https://facebookcorewwwi.onion
Creating new circuit #80000001 with 5.9.173.35:443 (killto; Tor 0.2.9.16) router...
Building 3 hops circuit...
Extending the circuit #80000001 with 54.39.151.167:9001 (DeusVult; Tor 0.3.5.8)...
Extending the circuit #80000001 with 171.25.193.78:443 (DFRI4; Tor 0.3.3.9)...
Creating stream #1 attached to #80000001 circuit...
Stream #1: connecting to ('facebookcorewwwi.onion', 443)
Extending #80000001 circuit for hidden service facebookcorewwwi.onion...
Rendezvous established (CellRelayRendezvousEstablished())
Iterate over responsible dirs of the hidden service
Iterate over introduction points of the hidden service
Create circuit for hsdir
Creating new circuit #80000002 with 5.9.173.35:443 (killto; Tor 0.2.9.16) router...
Building 0 hops circuit...
Extending the circuit #80000002 with 45.77.196.39:9001 (Fractalia; Tor 0.2.9.16)...
Creating stream #2 attached to #80000002 circuit...
Stream #2: connecting to hsdir
Stream #2: closing...
Destroy circuit #80000002
Creating new circuit #80000003 with 5.9.173.35:443 (killto; Tor 0.2.9.16) router...
Building 0 hops circuit...
Extending the circuit #80000003 with 213.136.81.89:9001 (unnamed314; Tor 0.3.5.8)...
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
tor = TorClient()
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
* `pip3 install torpy`


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
- [Mini-tor](https://github.com/wbenny/mini-tor)
- [Pycepa](https://github.com/pycepa/pycepa)
- [TorPylle](https://github.com/cea-sec/TorPylle)
- [TinyTor](https://github.com/Marten4n6/TinyTor)


[Python Versions]:      https://img.shields.io/badge/python-3.6,%203.7-blue.svg
[Issue]:                https://github.com/torpyorg/torpy/issues
[PR]:                   https://github.com/torpyorg/torpy/pulls