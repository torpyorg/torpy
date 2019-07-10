# Copyright 2019 James Brown
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import logging
import requests

from multiprocessing.pool import ThreadPool

from pytor import TorClient
from pytor.http.adapter import TorHttpAdapter
from pytor.http.requests import tor_requests_session
from pytor.hiddenservice import HiddenService
from pytor.utils import AuthType, recv_all


logging.getLogger('requests').setLevel(logging.CRITICAL)
logging.basicConfig(format="[%(asctime)s] [%(threadName)-16s] %(message)s", level=logging.DEBUG)
logger = logging.getLogger(__name__)


HS_BASIC_HOST = os.getenv('HS_BASIC_HOST')
HS_BASIC_AUTH = os.getenv('HS_BASIC_AUTH')

HS_STEALTH_HOST = os.getenv('HS_STEALTH_HOST')
HS_STEALTH_AUTH = os.getenv('HS_STEALTH_AUTH')


def test_clearnet_raw():
    hostname = 'ifconfig.me'
    tor = TorClient()
    # Choose random guard node and create 3-hops circuit
    with tor.create_circuit(3) as circuit:
        # Create tor stream to host
        with circuit.create_stream((hostname, 80)) as stream:
            # Send some data to it
            stream.send(b'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' % hostname.encode())
            recv = recv_all(stream).decode()
            logger.warning('recv: %s', recv)
            assert circuit.last_node.router.ip in recv, 'wrong data received'


def test_onion_raw():
    hostname = 'nzxj65x32vh2fkhk.onion'
    tor = TorClient()
    # Choose random guard node and create 3-hops circuit
    with tor.create_circuit(3) as circuit:
        # Create tor stream to host
        with circuit.create_stream((hostname, 80)) as stream:
            # Send some data to it
            stream.send(b'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' % hostname.encode())
            recv = stream.recv(1024).decode()
            logger.warning('recv: %s', recv)
            assert 'StickyNotes' in recv, 'wrong data received'


def test_requests():
    tor = TorClient()
    with tor.get_guard() as guard:
        adapter = TorHttpAdapter(guard, 3)

        with requests.Session() as s:
            s.headers.update({'User-Agent': 'Mozilla/5.0'})
            s.mount('http://', adapter)
            s.mount('https://', adapter)

            r = s.get('https://google.com')
            logger.warning(r)
            logger.warning(r.text)
            assert "</body></html>" in r.text

            r = s.get('https://cryptowat.ch/assets/btc')
            logger.warning(r)
            logger.warning(r.text)


def test_multi_threaded():
    auth_data = {HS_BASIC_HOST: (HS_BASIC_AUTH, AuthType.Basic)} if HS_BASIC_HOST and HS_BASIC_AUTH else None
    with tor_requests_session(auth_data=auth_data) as s:
        links = ['https://httpbin.org/headers', 'https://google.com', 'https://yahoo.com', 'http://facebookcorewwwi.onion']
        if HS_BASIC_HOST:
            links.append('http://' + HS_BASIC_HOST)
        links = links * 10

        def process(link):
            try:
                logger.debug("get link: %s", link)
                r = s.get(link, timeout=30)
                logger.warning("get link %s finish: %s", link, r)
                return r
            except:
                logger.exception("get link %s error", link)

        pool = ThreadPool(10)
        for i, w in enumerate(pool._pool):
            w.name = 'Worker{}'.format(i)
        results = pool.map(process, links)
        pool.close()
        pool.join()
    logger.debug("test_multi_threaded ends: %r", results)


def test_basic_auth():
    """Connecting to Hidden Service with 'Basic' authorization."""

    if not HS_BASIC_HOST or not HS_BASIC_AUTH:
        logger.warning("Skip test_basic_auth()")
        return

    hs = HiddenService(HS_BASIC_HOST, HS_BASIC_AUTH, AuthType.Basic)
    tor = TorClient()
    # Choose random guard node and create 3-hops circuit
    with tor.create_circuit(3) as circuit:
        # Create tor stream to host
        with circuit.create_stream((hs, 80)) as stream:
            # Send some data to it
            stream.send(b'GET /index.html HTTP/1.0\r\nHost: %s.onion\r\n\r\n' % hs.onion.encode())
            recv = recv_all(stream).decode()
            logger.warning('recv: %s', recv)


def test_stealth_auth():
    """Connecting to Hidden Service with 'Stealth' authorization."""

    if not HS_STEALTH_HOST or not HS_STEALTH_AUTH:
        logger.warning("Skip test_stealth_auth()")
        return

    hs = HiddenService(HS_STEALTH_HOST, HS_STEALTH_AUTH, AuthType.Stealth)
    tor = TorClient()
    # Choose random guard node and create 3-hops circuit
    with tor.create_circuit(3) as circuit:
        # Create tor stream to host
        with circuit.create_stream((hs, 80)) as stream:
            # Send some data to it
            stream.send(b'GET /index.html HTTP/1.0\r\nHost: %s\r\n\r\n' % hs.hostname.encode())
            recv = recv_all(stream).decode()
            logger.warning('recv: %s', recv)


def test_basic_auth_pre():
    """Using pre-defined authorization data for making HTTP requests."""

    if not HS_BASIC_HOST or not HS_BASIC_AUTH:
        logger.warning("Skip test_basic_auth()")
        return

    hidden_service = HS_BASIC_HOST
    auth_data = {HS_BASIC_HOST: (HS_BASIC_AUTH, AuthType.Basic)}
    tor = TorClient(auth_data=auth_data)
    # Choose random guard node and create 3-hops circuit
    with tor.create_circuit(3) as circuit:
        # Create tor stream to host
        with circuit.create_stream((hidden_service, 80)) as stream:
            # Send some data to it
            stream.send(b'GET /index.html HTTP/1.0\r\nHost: %s.onion\r\n\r\n' % hidden_service.encode())
            recv = recv_all(stream).decode()
            logger.warning('recv: %s', recv)


def test_requests_hidden():
    """Using pre-defined authorization data for making HTTP requests by tor_requests_session."""

    if not HS_BASIC_HOST or not HS_BASIC_AUTH:
        logger.warning("Skip test_requests_hidden()")
        return

    auth_data = {HS_BASIC_HOST: (HS_BASIC_AUTH, AuthType.Basic)}
    with tor_requests_session(auth_data=auth_data) as s:
        r = s.get('http://{}/index.html'.format(HS_BASIC_HOST))
        logger.warning(r)
        logger.warning(r.text)
