require('dotenv').config();
const bip39 = require('bip39');
const { BIP32Factory } = require('bip32');
const ecc = require('tiny-secp256k1');
const kaspaCore = require('@kaspa/core-lib');

const bip32 = BIP32Factory(ecc);

function deriveKaspaAddress() {
    try {
        const mnemonic = process.env.PERENNIA_TREASURY_SEED || "test test test test test test test test test test test junk";
        
        if (!bip39.validateMnemonic(mnemonic)) {
            throw new Error("Invalid mnemonic phrase provided.");
        }

        const seed = bip39.mnemonicToSeedSync(mnemonic);
        const root = bip32.fromSeed(seed);
        const kaspaPath = "m/44'/111111'/0'/0/0";
        const derivedNode = root.derivePath(kaspaPath);

        // ⚡ Raw buffer extraction (NO .toPrivateKey()!)
        if (!derivedNode.privateKey) {
            throw new Error("Failed to derive private key buffer.");
        }
        const rawPrivateKeyHex = derivedNode.privateKey.toString('hex');

        // Feed raw hex directly into the official Kaspa Core PrivateKey constructor
        const KaspaPrivateKey = kaspaCore.PrivateKey || kaspaCore.default?.PrivateKey;
        const kasPrivateKey = new KaspaPrivateKey(rawPrivateKeyHex);

        const kasAddress = kasPrivateKey.toPublicKey().toAddress('kaspa').toString();

        console.log("=========================================");
        console.log("🔑 KASPA SOVEREIGN DERIVATION SUCCESSFUL");
        console.log("=========================================");
        console.log(`Path:    ${kaspaPath}`);
        console.log(`Address: ${kasAddress}`);
        console.log("=========================================");

        return kasAddress;
    } catch (error) {
        console.error("🚨 Derivation Failed:", error.message);
    }
}

deriveKaspaAddress();