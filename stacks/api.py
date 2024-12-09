import urllib
import urllib.request
import json
from .block import Block
from .utils import bytes_to_hex


class StacksHttpException(Exception):
    pass


class StacksHttpTimeoutException(Exception):
    pass


class Api:

    def __init__(self, base_url="http://localhost:20443", timeout=30):
        self.base_url = base_url
        self.timeout = timeout

    def request_get(self, path):
        try:
            with urllib.request.urlopen(
                self.base_url + path, timeout=self.timeout
            ) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            raise StacksHttpException(
                "{} {}: {}".format(error.status, error.reason, error.fp.read().decode())
            ) from None
        except urllib.error.URLError as error:
            raise StacksHttpException(
                "{} {}: {}".format(error.status, error.reason, error.fp.read().decode())
            ) from None
        except TimeoutError:
            raise StacksHttpTimeoutException()

    def get_block_by_height(self, height):
        return Block.from_bytes(self.request_get("/v3/blocks/height/{}".format(height)))

    def get_block(self, index_block_hash):
        return Block.from_bytes(
            self.request_get("/v3/blocks/{}".format(bytes_to_hex(index_block_hash)))
        )

    def post_transaction(self, transaction):
        content = transaction.serialize()
        request = urllib.request.Request(
            self.base_url + "/v2/transactions",
            content,
            {"Content-Type": "application/octet-stream"},
        )
        request.get_method = lambda: "POST"
        try:
            with urllib.request.urlopen(request) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            print(error.status, error.reason, error.fp.read())
        except urllib.error.URLError as error:
            print(error.reason)
        except TimeoutError:
            print("Request timed out")

    def get_transaction(self, txid):
        return self.request_get("/v3/transactions/{}".format(txid))
