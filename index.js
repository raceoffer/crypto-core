const bcoin = require('bcoin');
const web3 = require('web3');
const bitcoincashjs = require('bitcoincashjs');

module.exports = {
  bcoin: bcoin,
  cashjs: bitcoincashjs,
  web3: web3,
  keyChain: require('./lib/keychain').set(bcoin),
  watchingWallet: require('./lib/watchingwallet').set(bcoin),
  blockCypherProvider: require('./lib/blockcypherprovider'),
  insightProvider: require('./lib/insightprovider').set(bcoin),
  blockchainInfoProvider: require('./lib/blockchaininfoprovider'),
  utils: require('./lib/utils').set(bcoin),
  compoundKey: require('./lib/compoundkey').set(bcoin),
  transaction: require('./lib/transaction/transaction'),
  bitcoinCashTransaction: require('./lib/transaction/bitcoincashtransaction'),
  bitcoinTransaction: require('./lib/transaction/bitcointransaction'),
  transaction: require('./lib/transaction/transaction'),
  schnorrProof: require('./lib/schnorrproof').set(bcoin),
  paillierProof: require('./lib/paillierproof'),
  pedersenScheme: require('./lib/pedersenscheme'),
  dds: require('./lib/dds').set(web3)
};
