from stacks.api import Api
from stacks.block import Block
from stacks.keys import generate_signing_and_verify_key
from stacks.hashing import ripemd160
from stacks.transaction import Transaction
import sys


private_key, public_key = generate_signing_and_verify_key()

api = Api()
data = api.get_block_by_height(int(sys.argv[1]))
print(data)
Block(data)

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