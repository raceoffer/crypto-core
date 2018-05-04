module.exports = {
  KeyChain: require('./lib/primitives/keychain'),

  BitcoinWallet: require('./lib/wallet/bitcore/bitcoinwallet'),
  BitcoinCashWallet: require('./lib/wallet/bitcore/bitcoincashwallet'),
  LitecoinWallet: require('./lib/wallet/bitcore/litecoinwallet'),
  EthereumWallet: require('./lib/wallet/ethereum/ethereumwallet'),
  ERC20Wallet: require('./lib/wallet/ethereum/erc20wallet'),

  BlockCypherProvider: require('./lib/provider/blockcypherprovider'),
  InsightProvider: require('./lib/provider/insightprovider'),
  BlockchainInfoProvider: require('./lib/provider/blockchaininfoprovider'),

  CompoundKey: require('./lib/primitives/compoundkey'),

  SchnorrProof: require('./lib/primitives/schnorrproof'),
  PaillierProver: require('./lib/primitives/paillierprover'),
  PaillierVerifier: require('./lib/primitives/paillierverifier'),
  PedersenScheme: require('./lib/primitives/pedersenscheme'),
  Signer: require('./lib/primitives/signer'),

  BitcoinTransaction: require('./lib/transaction/bitcore/bitcointransaction'),
  BitcoinCashTransaction: require('./lib/transaction/bitcore/bitcoincashtransaction'),
  LitecoinTransaction: require('./lib/transaction/bitcore/litecointransaction'),
  EthereumTransaction: require('./lib/transaction/ethereum/ethereumtransaction'),

  DDS: require('./lib/primitives/dds'),

  Utils: require('./lib/utils'),
  Marshal: require('./lib/marshal'),
  BN: require('bn.js')
};
