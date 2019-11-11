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

import logging
import textwrap
from argparse import ArgumentParser

from torpy.utils import register_logger
from torpy.http.urlopener import do_request as urllib_request
try:
    from torpy.http.requests import do_request as requests_request
except ImportError:
    requests_request = None

logger = logging.getLogger(__name__)


def print_data(data, to_file=None):
    if to_file:
        logger.info('Writing to file %s', to_file)
        with open(to_file, 'w+') as f:
            f.write(data)
    else:
        logger.warning(textwrap.indent(data, '> ', lambda line: True))


def main():
    parser = ArgumentParser()
    parser.add_argument('--url', help='url', required=True)
    parser.add_argument('--method', default='GET', type=str.upper, help='http method')
    parser.add_argument('--data', default=None, help='http data')
    parser.add_argument('--hops', default=3, help='hops count', type=int)
    parser.add_argument('--to-file', default=None, help='save result to file')
    parser.add_argument('--header', default=None, dest='headers', nargs=2, action='append', help='set some http header')
    parser.add_argument('--auth-data', nargs=2, action='append', help='set auth data for hidden service authorization')
    parser.add_argument('--log-file', default=None, help='log file path')
    parser.add_argument('--requests-lib', dest='request_func', default=urllib_request, action='store_const',
                        const=requests_request, help='use requests library for making requests')
    parser.add_argument('-v', '--verbose', default=0, help='enable verbose output', action='count')
    args = parser.parse_args()

    register_logger(args.verbose, log_file=args.log_file)

    if not args.request_func:
        raise Exception('Requests library not installed, use default urllib')

    data = args.request_func(args.url, method=args.method, data=args.data, headers=args.headers, hops=args.hops,
                             auth_data=args.auth_data, verbose=args.verbose)
    print_data(data, args.to_file)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.error('Interrupted.')
