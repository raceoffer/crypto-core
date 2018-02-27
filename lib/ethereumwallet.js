const EventEmitter = require('events');
const assert = require('assert');

function EthereumWallet(options) {
  if(!(this instanceof EthereumWallet))
    return new EthereumWallet(options);

  EventEmitter.call(this);

  this.accounts = [];
  this.loaded = false;

  this.network = null;
  this.web3 = null;
  this.routineTimer = null;
  this.balance = 0;

  if(options) {
    this.fromOptions(options);
  }
}

EthereumWallet.web3 = (typeof web3 !== 'undefined') ? web3 : null;

EthereumWallet.set = function (web3) {
  EthereumWallet.web3 = web3;
  return EthereumWallet;
};

EthereumWallet.Mainnet = 'main';
EthereumWallet.Testnet = 'testnet';

EthereumWallet.prototype.endpoint = function endpoint() {
  if(this.network === EthereumWallet.Mainnet) {
    return 'https://mainnet.infura.io';
  } else {
    return 'https://rinkeby.infura.io';
  }
};

EthereumWallet.prototype.fromOptions = function fromOptions(options) {
  if (options.network) {
    this.network = options.network;
  }
  this.web3 = new EthereumWallet.web3( new EthereumWallet.web3.providers.HttpProvider(this.endpoint() + '/' + options.infuraToken) );

  this.address = options.address;

  return this;
};

EthereumWallet.fromOptions = function fromOptions(options) {
  return new EthereumWallet().fromOptions(options);
};

Object.setPrototypeOf(EthereumWallet.prototype, EventEmitter.prototype);

EthereumWallet.prototype.load = async function load() {
  if (this.loaded) {
    return;
  }

  this.loaded = true;

  try {
    this.emit('balance', await this.getBalance());
  } catch(ignored) {}
  this.routineTimer = setInterval(async () => {
    let balance = 0;
    try {
      balance = await this.getBalance();
    } catch (ignored) {

    }
    if (balance !== this.balance) {
      this.balance = balance;
      this.emit('balance', balance);
    }
  },10000);

  return this;
};

EthereumWallet.prototype.getBalance = async function getBalance() {
  return await this.web3.eth.getBalance(this.address);
};

EthereumWallet.prototype.fill = async function fill(tx) {
  const [chainId, gasPrice, nonce] = await Promise.all([
    tx.chainId || this.web3.eth.net.getId(),
    tx.gasPrice || this.web3.eth.getGasPrice(),
    tx.nonce || this.web3.eth.getTransactionCount(tx.from)
  ]);

  tx.chainId = chainId;
  tx.gasPrice = gasPrice;
  tx.nonce = nonce;

  tx.gas = await this.web3.eth.estimateGas(tx);

  return tx;
};

EthereumWallet.prototype.sendSignedTransaction = async function(raw) {
  await this.web3.eth.sendSignedTransaction(raw);
};

EthereumWallet.prototype.fromWei = function fromWei(balance, type) {
  return this.web3.utils.fromWei(balance, type);
};

EthereumWallet.prototype.toWei = function fromWei(balance, type) {
  return this.web3.utils.toWei(balance, type);
};

module.exports = EthereumWallet;
