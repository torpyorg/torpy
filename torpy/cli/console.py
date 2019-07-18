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

from requests import Request

from torpy.http.requests import tor_requests_session
from torpy.utils import register_logger

logger = logging.getLogger(__name__)


def main():
    parser = ArgumentParser()
    parser.add_argument('--url', help='url', required=True)
    parser.add_argument('--method', default="GET", type=str.upper, help='http method')
    parser.add_argument('--data', default=None, help='http data')
    parser.add_argument('--hops', default=3, help='hops count', type=int)
    parser.add_argument('--to-file', default=None, help='save result to file')
    parser.add_argument('--header', dest='headers', nargs=2, action='append', help='set some http header')
    parser.add_argument('--auth-data', nargs=2, action='append', help='set auth data for hidden service authorization')
    parser.add_argument('-v', '--verbose', help='enable verbose output', action='store_true')
    args = parser.parse_args()

    register_logger(args.verbose)

    with tor_requests_session(args.hops, args.headers, args.auth_data) as s:
        request = Request(args.method, args.url, data=args.data)

        logger.warning("Sending: %s %s", request.method, request.url)
        response = s.send(request.prepare())

        logger.warning("Response status: %r", response.status_code)
        if args.to_file:
            logger.info("Writing to file %s", args.to_file)
            with open(args.to_file, "w+") as f:
                f.write(response.text)
        else:
            logger.warning(textwrap.indent(response.text, '> ', lambda line: True))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.error('Interrupted.')
