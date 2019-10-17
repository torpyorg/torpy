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

"""Socks5 repeater proxy."""
import os
import array
import select
import socket
import struct
import logging
import threading
from argparse import ArgumentParser
from contextlib import contextmanager

from torpy.utils import recv_exact, register_logger
from torpy.client import TorClient

logger = logging.getLogger(__name__)


class SocksProxy:
    def __init__(self, server_sock, client_sock):
        self.server_sock = server_sock
        self.client_sock = client_sock

    def run(self):
        ssock = self.server_sock
        csock = self.client_sock
        addr, port = csock.getsockname()
        csock.sendall(b'\x05\0\0\x01\x7f\0\0\x01' + struct.pack('!H', port))
        try:
            while True:
                r, w, _ = select.select([ssock, csock], [], [])
                if ssock in r:
                    buf = ssock.recv(4096)
                    if len(buf) == 0:
                        break
                    csock.send(buf)
                if csock in r:
                    buf = csock.recv(4096)
                    if len(buf) == 0:
                        break
                    ssock.send(buf)
        except BaseException:
            logger.exception('[socks] Some error')
        finally:
            logger.info('[socks] Close ssock')
            ssock.close()
            logger.info('[socks] Close csock')
            csock.close()


class SocksServer(object):
    def __init__(self, circuit, ip, port):
        self.circuit = circuit
        self.ip = ip
        self.port = port
        self.listen_socket = None

    def __enter__(self):
        """Start listen incoming connections."""
        lsock = self.listen_socket = socket.socket(2, 1, 6)
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind((self.ip, self.port))
        logger.info('Start socks proxy at %s:%s', self.ip, self.port)
        lsock.listen(0)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close listen incoming connections."""
        self.listen_socket.close()
        if exc_type:
            from traceback import format_exception

            logger.error(
                '[socks] Exception in server:\n%s',
                '\n'.join(format_exception(exc_type, exc_val, exc_tb)).rstrip('\r\n'),
            )

    def start(self):
        while True:
            try:
                csock, caddr = self.listen_socket.accept()
            except BaseException:
                logger.info('[socks] Closing by user request')
                raise
            logger.info('[socks] Client connected %s', caddr)
            Socks5(self.circuit, csock, caddr).start()


class Socks5(threading.Thread):
    def __init__(self, circuit, client_sock, client_addr):
        if client_addr[0] == '127.0.0.1':
            thread_name = 'Socks-%s' % client_addr[1]
        else:
            thread_name = 'Socks-%s:%s' % (client_addr[0], client_addr[1])
        super().__init__(name=thread_name)
        self.circuit = circuit
        self.client_sock = client_sock
        self.client_addr = client_addr

    def error(self, err=b'\x01\0'):
        try:
            self.client_sock.send(b'\x05' + err)
            self.client_sock.close()
            self.client_sock = None
        except BaseException:
            pass

    @contextmanager
    def create_socket(self, dst, port):
        logger.info('[socks] Connecting to %s:%s', dst, port)
        with self.circuit.create_stream((dst, port)) as tor_stream:
            yield tor_stream.create_socket()
            logger.debug('[socks] Closing stream #%x', tor_stream.id)

    def run(self):
        csock = self.client_sock
        try:
            ver = csock.recv(1)
            if ver != b'\x05':
                return self.error(b'\xff')
            nmeth, = array.array('B', csock.recv(1))
            _ = recv_exact(csock, nmeth)  # read methods
            csock.send(b'\x05\0')
            hbuf = recv_exact(csock, 4)
            if not hbuf:
                return self.error()

            ver, cmd, rsv, atyp = list(hbuf)
            if ver != 5 and cmd != 1:
                return self.error()

            if atyp == 1:
                dst = '.'.join(str(i) for i in recv_exact(csock, 4))
            elif atyp == 3:
                n, = array.array('B', csock.recv(1))
                dst = recv_exact(csock, n).decode()
            elif atyp == 4:
                dst = ':'.join(recv_exact(csock, 2).hex() for _ in range(8))
                # TODO: ipv6
                return self.error()
            else:
                return self.error()

            port = int(recv_exact(csock, 2).hex(), 16)

            with self.create_socket(dst, port) as ssock:
                SocksProxy(ssock, csock).run()
        except Exception:
            logger.exception('[socks] csock close by exception')
            csock.close()
            self.client_sock = None


def main():
    parser = ArgumentParser(description=__doc__, prog=os.path.basename(__file__))
    parser.add_argument('-i', '--ip', default='127.0.0.1', help='ip address to bind to')
    parser.add_argument('-p', '--port', default=1050, type=int, help='bind port')
    parser.add_argument('--hops', default=3, help='hops count', type=int)
    parser.add_argument('-v', '--verbose', help='enable verbose output', action='store_true')
    args = parser.parse_args()

    register_logger(args.verbose)

    tor = TorClient()
    with tor.create_circuit(args.hops) as circuit, SocksServer(circuit, args.ip, args.port) as socks_serv:
        socks_serv.start()


if __name__ == '__main__':
    main()
