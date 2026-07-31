use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::opcodes::codes::{OpCheckSig, OpEqual};
use kaspa_addresses::{Address, Prefix};
use kaspa_consensus_core::tx::{ScriptPublicKey, ScriptVec};

/// ⚡ SILVERSCRIPT TN12 PAYLOAD
/// This represents our Smart Order Router Covenant in raw Silverscript.
/// Once Toccata is fully live, this text payload will be ingested by the VM directly.
/// For Phase 1, we use this as the reference and compile it natively into Kaspa opcodes.
pub const SOR_COVENANT_SIL: &str = r#"
// Silverscript v1.0 - TN12 Toccata
// Perennia Smart Order Router Ephemeral Covenant
contract SORRouteLock(
    pubkey admin_key,
    int max_slippage
) {
    function rebalance(sig admin_sig) {
        // 1. Verify admin authorization via Schnorr
        require(checkSig(admin_sig, admin_key));
        
        // 2. Toccata Introspection (Enforce Slippage & Routing Natively)
        // require(tx.output[0].value >= (tx.input[0].value * (100 - max_slippage)) / 100);
    }
}
"#;

pub struct SilverscriptCompiler;

impl SilverscriptCompiler {
    /// Compiles a `.sil` equivalent string payload into Kaspa-native VM bytecode.
    pub fn compile_sor_covenant(admin_pubkey_bytes: &[u8]) -> ScriptPublicKey {
        let script = ScriptBuilder::new()
            .add_data(admin_pubkey_bytes).expect("Failed to push admin pubkey to stack")
            .add_op(OpCheckSig).expect("Failed to append OP_CHECKSIG")
            .drain();

        // Convert Vec<u8> to ScriptVec (SmallVec) using .into()
        ScriptPublicKey::new(0, script.into())
    }

    /// Takes compiled bytecode and mathematically derives a P2SH (Pay-to-Script-Hash) Kaspa Address.
    pub fn derive_p2sh_address(redeem_script: &[u8]) -> Address {
        let spk = kaspa_txscript::pay_to_script_hash_script(redeem_script);
        kaspa_txscript::extract_script_pub_key_address(&spk, Prefix::Testnet)
            .expect("Failed to extract address from P2SH SPK")
    }

    /// 🧪 PHASE 1.5 TEST HARNESS: "Hello World" Math-Lock Covenant
    /// Emits: OP_PUSH1 0x42 OP_EQUAL
    pub fn compile_test_lock() -> (ScriptVec, Address) {
        // The script requires the spender to push exactly 0x42 to the stack.
        let script = ScriptBuilder::new()
            .add_data(&[0x42]).expect("Failed to push 0x42 argument")
            .add_op(OpEqual).expect("Failed to push OP_EQUAL")
            .drain();
        
        let addr = Self::derive_p2sh_address(&script);
        
        // Convert Vec<u8> to ScriptVec (SmallVec) using .into()
        (script.into(), addr)
    }
}