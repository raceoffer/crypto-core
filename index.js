module.exports = {
  KeyChain: require('./lib/keychain'),
  WatchingWallet: require('./lib/watchingwallet'),
  BlockCypherProvider: require('./lib/blockcypherprovider'),
  InsightProvider: require('./lib/insightprovider'),
  BlockchainInfoProvider: require('./lib/blockchaininfoprovider'),
  Utils: require('./lib/utils'),
  CompoundKey: require('./lib/compoundkey'),
  BitcoreTransaction: require('./lib/bitcore/bitcoretransaction'),
  BitcoinCashTransaction: require('./lib/bitcore/bitcoincashtransaction'),
  BitcoinTransaction: require('./lib/bitcore/bitcointransaction'),
  EthereumTransaction: require('./lib/ethereum/ethereumtransaction'),
  SchnorrProof: require('./lib/schnorrproof'),
  PaillierProof: require('./lib/paillierproof'),
  PedersenScheme: require('./lib/pedersenscheme'),
  DDS: require('./lib/dds'),
  EthereumWallet: require('./lib/ethereumwallet'),
  ERC20Wallet: require('./lib/erc20Wallet')
};
