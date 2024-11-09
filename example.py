from stacks.api import Api
from stacks.block import Block
import sys

api = Api()
data = api.get_block_by_height(int(sys.argv[1]))
print(data)
Block(data)
