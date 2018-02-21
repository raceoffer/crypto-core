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
  utils: require('./lib/utils'),
  compoundKey: require('./lib/compoundkey'),
  bitcoreTransaction: require('./lib/bitcore/bitcoretransaction'),
  bitcoinCashTransaction: require('./lib/bitcore/bitcoincashtransaction'),
  bitcoinTransaction: require('./lib/bitcore/bitcointransaction'),
  ethereumTransaction: require('./lib/ethereum/ethereumtransaction'),
  schnorrProof: require('./lib/schnorrproof').set(bcoin),
  paillierProof: require('./lib/paillierproof'),
  pedersenScheme: require('./lib/pedersenscheme'),
  dds: require('./lib/dds').set(web3),
  ethereumWallet: require('./lib/ethereumwallet').set(web3),
  currency: require('./lib/currency/currency').set(bcoin)
};
