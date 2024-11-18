import struct

"""

pub struct StacksTransaction {
    pub version: TransactionVersion,
    pub chain_id: u32,
    pub auth: TransactionAuth,
    pub anchor_mode: TransactionAnchorMode,
    pub post_condition_mode: TransactionPostConditionMode,
    pub post_conditions: Vec<TransactionPostCondition>,
    pub payload: TransactionPayload,
}


pub enum TransactionVersion {
    Mainnet = 0x00,
    Testnet = 0x80,
}

pub enum TransactionAuthFlags {
    // types of auth
    AuthStandard = 0x04,
    AuthSponsored = 0x05,
}

pub enum TransactionAuthFieldID {
    // types of auth fields
    PublicKeyCompressed = 0x00,
    PublicKeyUncompressed = 0x01,
    SignatureCompressed = 0x02,
    SignatureUncompressed = 0x03,
}

pub enum SinglesigHashMode {
    P2PKH = 0x00,
    P2WPKH = 0x02,
}

fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(self.hash_mode.clone() as u8))?;
        write_next(fd, &self.signer)?;
        write_next(fd, &self.nonce)?;
        write_next(fd, &self.tx_fee)?;
        write_next(fd, &(self.key_encoding.clone() as u8))?;
        write_next(fd, &self.signature)?;
        Ok(())
    }
    
/// Post-condition modes for unspecified assets
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum TransactionPostConditionMode {
    Allow = 0x01, // allow any other changes not specified
    Deny = 0x02,  // deny any other changes not specified
}

/// Stacks transaction versions
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum TransactionVersion {
    Mainnet = 0x00,
    Testnet = 0x80,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StacksTransaction {
    pub version: TransactionVersion,
    pub chain_id: u32,
    pub auth: TransactionAuth,
    pub anchor_mode: TransactionAnchorMode,
    pub post_condition_mode: TransactionPostConditionMode,
    pub post_conditions: Vec<TransactionPostCondition>,
    pub payload: TransactionPayload,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionPayload {
    TokenTransfer(PrincipalData, u64, TokenTransferMemo),
    ContractCall(TransactionContractCall),
    SmartContract(TransactionSmartContract, Option<ClarityVersion>),
    // the previous epoch leader sent two microblocks with the same sequence, and this is proof
    PoisonMicroblock(StacksMicroblockHeader, StacksMicroblockHeader),
    Coinbase(CoinbasePayload, Option<PrincipalData>, Option<VRFProof>),
    TenureChange(TenureChangePayload),
}
"""

class Transaction:

    def __init__(self, signer):
        self.version = 0x80
        self.chain_id = 0x80000000
        self.auth = 0
        self.anchor_mode = 0
        self.post_condition_mode = 0
        self.post_conditions = []
        self.payload = b''
        
        
    def serialize(self):
        blob = struct.pack('>BI', self.version, self.chain_id)
        
        # auth Standard + SingleSig(SinglesigSpendingCondition)
        blob += struct.pack('>B', 0x04 )

        return blob