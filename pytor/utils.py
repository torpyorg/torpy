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

import sys
import logging
import threading
import contextlib

from base64 import b64encode


logger = logging.getLogger(__name__)


def register_logger(verbose):
    fmt = '[%(asctime)s] [%(threadName)-16s] %(message)s' if verbose else '%(message)s'
    lvl = logging.DEBUG if verbose else logging.INFO
    if not verbose:
        logging.getLogger('requests').setLevel(logging.CRITICAL)
    logging.basicConfig(format=fmt, level=lvl)


def to_hex(b):
    return ' '.join('{:02x}'.format(x) for x in b)


def fp_to_str(fp):
    return b64encode(fp).decode()


class cached_property:
    def __init__(self, func):
        self.__doc__ = func.__doc__
        self.func = func
        self.lock = threading.RLock()

    def __get__(self, obj, cls):
        if obj is None:
            return self

        with self.lock:
            value = obj.__dict__[self.func.__name__] = self.func(obj)
            return value


def log_retry(exc_info, msg):
    logger.error(exc_info[1])
    logger.info(msg)


def retry(times, exceptions, log_func=None):
    def decorator(func):
        def newfn(*args, **kwargs):
            attempts = times
            while attempts:
                try:
                    return func(*args, **kwargs)
                except exceptions:
                    if log_func:
                        exc_info = sys.exc_info()
                        log_func(exc_info)
                        del exc_info
                    else:
                        logger.info(
                            'Exception thrown when attempting to run %s, attempt %d of %d', func, attempts, times,
                            exc_info=True)
                    attempts -= 1
                    if not attempts:
                        raise
        return newfn
    return decorator


@contextlib.contextmanager
def ignore(comment, exceptions=None, log_func=None):
    exceptions = exceptions or (Exception, )
    try:
        yield
    except exceptions:
        if log_func:
            exc_info = sys.exc_info()
            log_func(exc_info, comment)
            del exc_info
        else:
            logger.info(comment, exc_info=True)


def scheme_to_port(scheme):
    if scheme == 'http':
        return 80
    elif scheme == 'https':
        return 443
    elif scheme == 'ftp':
        return 21


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def recv_exact(sock, n):
    data = b''
    while n:
        chunk = sock.recv(n)
        if not chunk:
            break
        n -= len(chunk)
        data += chunk
        #if n:
        #    logger.debug("recv_exact: not all data was recv'd, trying again...")
    return data


def recv_all(sock):
    """Receive data until connection is closed."""
    data = b''
    while True:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    return data


class AuthType:
    No = 0
    Basic = 1
    Stealth = 2
