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
import sys
import gzip
import zlib
import time
import logging
import threading
import contextlib
from base64 import b64encode
from urllib import request

logger = logging.getLogger(__name__)


def register_logger(verbose, log_file=None):
    fmt = '[%(asctime)s] [%(threadName)-16s] %(message)s' if verbose else '%(message)s'
    lvl = logging.DEBUG if verbose else logging.INFO
    if not verbose:
        logging.getLogger('requests').setLevel(logging.CRITICAL)
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(format=fmt, level=lvl, handlers=handlers)


def to_hex(b):
    return ' '.join('{:02x}'.format(x) for x in b)


def fp_to_str(fp):
    return b64encode(fp).decode()


class cached_property:  # noqa: N801
    def __init__(self, func):
        self.__doc__ = func.__doc__
        self.func = func
        self.lock = threading.RLock()

    def __get__(self, obj, cls):
        """Check whether return value already exists and return it."""
        if obj is None:
            return self

        with self.lock:
            value = obj.__dict__[self.func.__name__] = self.func(obj)
            return value


def log_retry(exc_info, msg, no_traceback=None):
    if no_traceback is not None and exc_info[0] not in no_traceback:
        logging.error('[ignored]', exc_info=exc_info[1])
    else:
        logger.error('[ignored] %s.%s: %s', exc_info[0].__module__, exc_info[0].__qualname__, str(exc_info[1]))
    logger.warning(msg)


def retry(times, exceptions, delay=1, backoff=0, log_func=None):
    def decorator(func):
        def newfn(*args, **kwargs):
            left = times
            while left:
                try:
                    return func(*args, **kwargs)
                except exceptions:
                    if log_func:
                        exc_info = sys.exc_info()
                        try:
                            log_func(exc_info)
                        finally:
                            del exc_info
                    else:
                        logger.info(
                            'Exception thrown when attempting to run %s, attempt %d of %d',
                            func,
                            times - left,
                            times,
                            exc_info=True,
                        )
                    left -= 1
                    if not left:
                        raise
                    if delay:
                        total_delay = delay + (times - left) * backoff
                        logger.info('Wait %i sec before next retry', total_delay)
                        time.sleep(total_delay)

        return newfn

    return decorator


@contextlib.contextmanager
def ignore(comment, exceptions=None, log_func=None):
    exceptions = exceptions or (Exception,)
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


def chunks(lst, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def recv_exact(sock, n):
    data = b''
    while n:
        chunk = sock.recv(n)
        if not chunk:
            break
        n -= len(chunk)
        data += chunk
    return data


def coro_recv_exact(n):
    data = b''
    while n:
        chunk = yield n
        if not chunk:
            break
        n -= len(chunk)
        data += chunk
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


def user_data_dir(app_name):
    """Return full path to the user-specific data dir for this application."""
    if sys.platform == 'win32':
        app_name = os.path.join(app_name, app_name)  # app_author + app_name
        path = os.path.expandvars(r'%APPDATA%')
    elif sys.platform == 'darwin':
        path = os.path.expanduser('~/Library/Application Support/')
    else:
        path = os.getenv('XDG_DATA_HOME', os.path.expanduser('~/.local/share'))
    return os.path.join(path, app_name)


def http_get(url, timeout=10, headers=None):
    opener = request.build_opener()

    real_headers = {'Accept-encoding': 'gzip, deflate'}
    real_headers.update(headers or {})
    opener.addheaders = [(k, v) for k, v in real_headers.items()]

    with opener.open(url, timeout=timeout) as response:
        data = response.read()
        if response.info().get('Content-Encoding') == 'gzip':
            data = gzip.decompress(data)
        elif response.info().get('Content-Encoding') == 'deflate':
            data = zlib.decompress(data)
        return data.decode('utf-8')


def hostname_key(hostname):
    return '.'.join(hostname.split('.')[-2:])
