export { KeyChain } from './lib/primitives/keychain';

export { BitcoinWallet } from './lib/wallet/bitcore/bitcoinwallet';
export { BitcoinCashWallet } from './lib/wallet/bitcore/bitcoincashwallet';
export { LitecoinWallet } from './lib/wallet/bitcore/litecoinwallet';
export { EthereumWallet } from './lib/wallet/ethereum/ethereumwallet';
export { ERC20Wallet } from './lib/wallet/ethereum/erc20wallet';
export { NemWallet } from "./lib/wallet/nem/nemwallet";
export { NeoWallet } from "./lib/wallet/neo/neowallet";

export { InsightProvider } from './lib/provider/insightprovider';

export { KeyPair } from './lib/primitives/eddsa/keypair';

export { DistributedKey as DistributedKeyEcdsa, DistributedKeyShard as DistributedKeyShardEcdsa } from './lib/primitives/ecdsa/distributedkey';

export { PaillierPublicKey, PaillierSecretKey } from './lib/primitives/ecdsa/paillierkeys';

export { SchnorrProof } from './lib/primitives/schnorrproof';
export { PedersenScheme } from './lib/primitives/pedersenscheme';
export { PaillierProver, InitialCommitment, InitialDecommitment, ResponseCommitment, ProverSyncData, ResponseDecommitment } from './lib/primitives/ecdsa/paillierprover';
export { PaillierVerifier, InitialData, ChallengeCommitment, ChallengeDecommitment, VerifierSyncData } from './lib/primitives/ecdsa/paillierverifier';
export { Signer as SignerEcdsa } from './lib/primitives/ecdsa/signer';
export { Signer as SignerEddsa } from './lib/primitives/eddsa/signer';

export { BitcoinTransaction } from './lib/transaction/bitcore/bitcointransaction';
export { BitcoinCashTransaction } from './lib/transaction/bitcore/bitcoincashtransaction';
export { LitecoinTransaction } from './lib/transaction/bitcore/litecointransaction';
export { EthereumTransaction } from './lib/transaction/ethereum/ethereumtransaction';
export { NemTransaction } from './lib/transaction/nem/nemtransaction';
export { NeoTransaction } from './lib/transaction/neo/neotransaction';

export { DDS } from './lib/primitives/dds';

export { Curve, matchCurve } from './lib/curves';

import * as Convert from './lib/convert';
export { Convert };

import * as Utils from './lib/utils';
export { Utils };

import * as Marshal from './lib/marshal';
export { Marshal };
