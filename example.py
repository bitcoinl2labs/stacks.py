from stacks.api import Api
from stacks.block import Block
from stacks.keys import generate_signing_and_verify_key
from stacks.hashing import ripemd160
from stacks.transaction import Transaction
from stacks.serializable import hex_to_bytes
import sys


private_key, public_key = generate_signing_and_verify_key()

api = Api()
#data = api.get_block_by_height(int(sys.argv[1]))
#print(data)
#Block(data)

tx = api.get_transaction('65c036b923f1f0017bbc3d5bdb078b4cf797032a8a5c613c89a16b7aeba3bb7a')
print(tx)

tx_data = hex_to_bytes(tx['tx'])
print(tx_data)

transaction = Transaction().from_bytes(tx_data)
print(transaction)

"""
pub fn new(
        version: TransactionVersion,
        auth: TransactionAuth,
        payload: TransactionPayload,
    ) -> StacksTransaction {
        let anchor_mode = match payload {
            TransactionPayload::Coinbase(..) => TransactionAnchorMode::OnChainOnly,
            TransactionPayload::PoisonMicroblock(_, _) => TransactionAnchorMode::OnChainOnly,
            _ => TransactionAnchorMode::Any,
        };

        StacksTransaction {
            version: version,
            chain_id: 0,
            auth: auth,
            anchor_mode: anchor_mode,
            post_condition_mode: TransactionPostConditionMode::Deny,
            post_conditions: vec![],
            payload: payload,
        }
    }
"""

"""
print(ripemd160(public_key).digest())

print(len(ripemd160(public_key).digest()))

signer = ripemd160(public_key).digest()

api.post_transaction(Transaction(signer))
"""