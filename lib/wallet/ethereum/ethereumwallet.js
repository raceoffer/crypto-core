const eth = require('eth-lib');
const Web3 = require('web3');
const unit = require('ethjs-unit');
const BN = require('bn.js');

function EthereumWallet() {
  this.network = null;
  this.address = null;

  this.web3 = null;
}

EthereumWallet.address = function(key) {
  const publicKey = '0x' + key.encode('hex', false).slice(2);
  const publicHash = eth.hash.keccak256(publicKey);
  return eth.account.toChecksum('0x' + publicHash.slice(-40));
};

EthereumWallet.Mainnet = 'main';
EthereumWallet.Testnet = 'testnet';

EthereumWallet.prototype.fromOptions = function(options) {
  this.network = options.network || EthereumWallet.Mainnet;
  this.address = EthereumWallet.address(options.key);
  this.endpoint = options.endpoint;

  this.web3 = new Web3( new Web3.providers.HttpProvider(this.endpoint) );

  return this;
};

EthereumWallet.fromOptions = function(options) {
  return new EthereumWallet().fromOptions(options);
};

EthereumWallet.prototype.getBalance = async function() {
  const balance = await this.web3.eth.getBalance(this.address);
  return {
    confirmed: new BN(balance),
    unconfirmed: new BN(balance)
  };
};

EthereumWallet.prototype.prepareTransaction = async function(transaction, to, value, fee) {
  const [chainId, gasPrice, nonce] = await Promise.all([
    this.web3.eth.net.getId(),
    this.web3.eth.getGasPrice(),
    this.web3.eth.getTransactionCount(this.address)
  ]);

  const tx = {
    chainId: chainId,
    gasPrice: gasPrice,
    nonce: nonce,
    from: this.address,
    value: value,
    to: to
  };

  tx.gas = await this.web3.eth.estimateGas(tx);

  if (fee) {
    tx.gasPrice = fee.div(new BN(tx.gas)).toNumber();
  }

  return await transaction.fromOptions(tx, false);
};

EthereumWallet.prototype.sendSignedTransaction = async function(raw) {
  await this.web3.eth.sendSignedTransaction(raw);
};

EthereumWallet.prototype.fromInternal = function(value) {
  return parseFloat(unit.fromWei(value, 'ether'));
};

EthereumWallet.prototype.toInternal = function(value) {
  return unit.toWei(parseFloat(value).toFixed(18), 'ether');
};

module.exports = EthereumWallet;
