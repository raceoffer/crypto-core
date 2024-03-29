const { KeyChain } = require('./lib/primitives/keychain');

const { InsightProvider } = require('./lib/provider/insightprovider');

const { BitcoinWallet } = require('./lib/wallet/bitcore/bitcoinwallet');
const { BitcoinCashWallet } = require('./lib/wallet/bitcore/bitcoincashwallet');
const { LitecoinWallet } = require('./lib/wallet/bitcore/litecoinwallet');
const { EthereumWallet } = require('./lib/wallet/ethereum/ethereumwallet');
const { ERC20Wallet } = require('./lib/wallet/ethereum/erc20wallet');
const { NemWallet } = require("./lib/wallet/nem/nemwallet");
const { NeoWallet } = require("./lib/wallet/neo/neowallet");

const { SchnorrProof } = require('./lib/primitives/schnorrproof');
const { PedersenScheme } = require('./lib/primitives/pedersenscheme');

const { PaillierPublicKey, PaillierSecretKey } = require('./lib/primitives/ecdsa/paillierkeys');
const { EddsaKeyPair } = require('./lib/primitives/eddsa/eddsakeypair');

const { DistributedEcdsaKey, DistributedEcdsaKeyShard } = require('./lib/primitives/ecdsa/distributedecdsakey');
const { DistributedEddsaKey } = require('./lib/primitives/eddsa/distributededdsakey');

const {
  DistributedEcdsaSyncSession,
  DistributedEcdsaSyncSessionShard,
  EcdsaInitialCommitment,
  EcdsaInitialDecommitment,
  EcdsaInitialData,
  EcdsaChallengeCommitment,
  EcdsaChallengeDecommitment,
  EcdsaResponseCommitment,
  EcdsaResponseDecommitment,
  EcdsaSyncData,
  EcdsaShardSyncData
} = require('./lib/primitives/ecdsa/distributedecdsasyncsession');

const {
  DistributedEcdsaSignSession,
  DistributedEcdsaSignSessionShard,
  EcdsaEntropyCommitment,
  EcdsaEntropyDecommitment,
  EcdsaEntropyData,
  EcdsaPartialSignature,
  EcdsaSignature
} = require('./lib/primitives/ecdsa/distributedecdsasignsession');

const {
  DistributedEddsaSyncSession,
  DistributedEddsaSyncSessionShard,
  EddsaCommitment,
  EddsaDecommitment,
  EddsaData,
  EddsaSyncData
} = require('./lib/primitives/eddsa/distributededdsasyncsession');

const {
  DistributedEddsaSignSession,
  DistributedEddsaSignSessionShard,
  EddsaEntropyCommitment,
  EddsaEntropyDecommitment,
  EddsaEntropyData,
  EddsaPartialSignature,
  EddsaSignature
} = require('./lib/primitives/eddsa/distributededdsasignsession');

const {
  BitcoreSignSession,
  BitcoreSignSessionShard,
  BitcoreEntropyCommitment,
  BitcoreEntropyDecommitment,
  BitcoreEntropyData,
  BitcorePartialSignature,
  BitcoreSignature
} = require('./lib/transaction/bitcore/bitcoretransaction');

const { BitcoinTransaction } = require('./lib/transaction/bitcore/bitcointransaction');
const { BitcoinCashTransaction } = require('./lib/transaction/bitcore/bitcoincashtransaction');
const { LitecoinTransaction } = require('./lib/transaction/bitcore/litecointransaction');
const { EthereumTransaction } = require('./lib/transaction/ethereum/ethereumtransaction');
const { NeoTransaction } = require('./lib/transaction/neo/neotransaction');
const { NemTransaction } = require('./lib/transaction/nem/nemtransaction');

const { DDS } = require('./lib/primitives/dds');

const { Curve } = require('./lib/curves');

const Convert = require('./lib/convert');
const Utils = require('./lib/utils');
const Marshal = require('./lib/marshal');

module.exports = {
  KeyChain,
  InsightProvider,
  BitcoinWallet,
  LitecoinWallet,
  BitcoinCashWallet,
  EthereumWallet,
  ERC20Wallet,
  NemWallet,
  NeoWallet,
  SchnorrProof,
  PedersenScheme,
  PaillierPublicKey,
  PaillierSecretKey,
  DistributedEcdsaKey,
  DistributedEcdsaKeyShard,
  DistributedEcdsaSyncSession,
  DistributedEcdsaSyncSessionShard,
  EcdsaInitialCommitment,
  EcdsaInitialDecommitment,
  EcdsaInitialData,
  EcdsaChallengeCommitment,
  EcdsaChallengeDecommitment,
  EcdsaResponseCommitment,
  EcdsaResponseDecommitment,
  EcdsaSyncData,
  EcdsaShardSyncData,
  EddsaKeyPair,
  DistributedEddsaKey,
  DistributedEddsaSyncSession,
  DistributedEddsaSyncSessionShard,
  EddsaCommitment,
  EddsaDecommitment,
  EddsaData,
  EddsaSyncData,
  DistributedEcdsaSignSession,
  DistributedEcdsaSignSessionShard,
  EcdsaEntropyCommitment,
  EcdsaEntropyDecommitment,
  EcdsaEntropyData,
  EcdsaPartialSignature,
  EcdsaSignature,
  BitcoinTransaction,
  BitcoinCashTransaction,
  LitecoinTransaction,
  EthereumTransaction,
  NeoTransaction,
  NemTransaction,
  DDS,
  Curve,
  Convert,
  Marshal,
  Utils
};
