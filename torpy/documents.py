from datetime import datetime
from base64 import b64decode

from torpy.router import RouterFlags, OnionRouter


class TorDocument:
    DOCUMENT_NAME = None

    def __init__(self, raw_string, **kwargs):
        self._raw_string = raw_string

    @property
    def raw_string(self):
        return self._raw_string


class TorConsensusDocument(TorDocument):
    DOCUMENT_NAME = 'network_status'

    def __init__(self, raw_string, link_consensus):
        super().__init__(raw_string)
        parser = TorConsensusParser()
        self._routers_list, self._voters_list, self._valid_after, self._fresh_until, self._valid_until = parser.parse(
            raw_string, link_consensus)

    @property
    def routers_list(self):
        return self._routers_list

    @property
    def is_fresh(self):
        return self._valid_until > datetime.utcnow()


class TorConsensusParser:
    def __init__(self, validate_flags=None):
        self.validate_flags = validate_flags or [RouterFlags.stable, RouterFlags.fast, RouterFlags.valid,
                                                 RouterFlags.running]

    @staticmethod
    def _parse_r_line(line):
        """
        Parse router info line.

        :param line: the line
        :return: dict with router info
        """
        split_line = line.split(' ')

        nickname = split_line[1]
        fingerprint = split_line[2]
        ip = split_line[6]
        tor_port = int(split_line[7])
        dir_port = int(split_line[8])

        # The fingerprint is base64 encoded bytes.
        fingerprint += '=' * (-len(fingerprint) % 4)
        fingerprint = b64decode(fingerprint)

        return {'nickname': nickname, 'ip': ip, 'dir_port': dir_port, 'tor_port': tor_port, 'fingerprint': fingerprint}

    @staticmethod
    def _parse_s_line(line):
        flags = []
        for token in line.split(' '):
            if token == 's':
                continue
            flags.append(token.lower().replace('\n', '', 1))
        return flags

    @staticmethod
    def _parse_dir_line(line):
        #  dannenberg 0232AF901C31A04EE9848595AF9BB7620D4C5B2E dannenberg.torauth.de 193.23.244.244 80 443
        split_line = line.split(' ')[1:]
        fields = ['nickname', 'fingerprint', 'hostname', 'address', 'dir_port', 'or_port']
        return dict(zip(fields, split_line))

    @staticmethod
    def _to_flags(flags_list):
        flags = RouterFlags.unknown
        for f in RouterFlags:
            if f.name in flags_list:
                flags |= f
        return flags

    @staticmethod
    def _parse_date(date_str):
        # 2019-01-01 00:00:00
        return datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')

    def parse(self, consensus_string, link_consensus=None):
        results_list = []
        voters_list = []
        valid_after = fresh_until = valid_until = None

        router_info = None
        voter_info = None
        for line in consensus_string.splitlines():
            # Consensus info
            if line.startswith('valid-after '):
                valid_after = self._parse_date(line[12:])
            elif line.startswith('fresh-until '):
                fresh_until = self._parse_date(line[12:])
            elif line.startswith('valid-until '):
                valid_until = self._parse_date(line[12:])
            # Voters lines
            elif line.startswith('dir-source '):
                voter_info = self._parse_dir_line(line)
            elif line.startswith('contact '):
                voter_info['contact'] = line[8:]
            elif line.startswith('vote-digest '):
                voter_info['vote_digest'] = line[12:]
                voters_list.append(voter_info)
            # Router lines
            elif line.startswith('r '):
                router_info = self._parse_r_line(line)
            elif line.startswith('s '):
                assert router_info
                flags_list = self._parse_s_line(line)
                router_info['flags'] = self._to_flags(flags_list)
            elif line.startswith('v '):
                assert router_info
                assert router_info['flags']

                if router_info['flags'].all_present(self.validate_flags):
                    router_info['version'] = line[2:]

                    router = OnionRouter(**router_info, consensus=link_consensus)
                    results_list.append(router)
                router_info = None
            # Signatures lines
            elif line.startswith('directory-signature '):
                pass
            # TODO: calculate SHA1/SHA256

        return results_list, voters_list, valid_after, fresh_until, valid_until
