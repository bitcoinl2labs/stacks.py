import urllib
import urllib.request

class Api:

    def __init__(self, base_url='http://localhost:20443'):
        self.base_url = base_url

    def get_block_by_height(self, height):
        try:
            with urllib.request.urlopen(self.base_url + '/v3/blocks/height/{}'.format(height)) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            print(error.status, error.reason, error.fp.read())
        except urllib.error.URLError as error:
            print(error.reason)
        except TimeoutError:
            print("Request timed out")
        
    def post_transaction(self, transaction):
        content = transaction.serialize()
        request = urllib.request.Request(self.base_url + '/v2/transactions', content,
                    {'Content-Type': 'application/octet-stream'})
        request.get_method = lambda: 'POST'
        try:
            with urllib.request.urlopen(request) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            print(error.status, error.reason, error.fp.read())
        except urllib.error.URLError as error:
            print(error.reason)
        except TimeoutError:
            print("Request timed out")