import urllib
import urllib.request

class Api:

    def __init__(self, base_url='http://localhost:20443'):
        self.base_url = base_url

    def get_block_by_height(self, height):
        with urllib.request.urlopen(self.base_url + '/v3/blockbyheight/{}'.format(height)) as response:
            return response.read()