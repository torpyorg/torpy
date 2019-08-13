from torpy.documents.network_status import NetworkStatusDocument
from torpy.documents.network_status_diff import NetworkStatusDiffDocument


class TorDocumentsFactory:
    DOCUMENTS = [
        NetworkStatusDocument,
        NetworkStatusDiffDocument
    ]

    @staticmethod
    def parse(raw_string, kwargs=None, possible=None):
        kwargs = kwargs or {}
        possible = possible or TorDocumentsFactory.DOCUMENTS

        for doc_cls in possible:
            if doc_cls.check_start(raw_string):
                return doc_cls(raw_string, **kwargs)

        return None
