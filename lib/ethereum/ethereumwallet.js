const eth = require('eth-lib');
const Web3 = require('web3');

function EthereumWallet() {
  this.address = null;
  this.loaded = false;

  this.network = null;
  this.web3 = null;
  this.balance = 0;
}

EthereumWallet.formatPublic = function(key) {
  return '0x' + key.encode('hex', false).slice(2);
};

EthereumWallet.formatPrivate = function(key) {
  return '0x' + key.toString(16);
};

EthereumWallet.address = function(key) {
  const publicKey = this.formatPublic(key);
  const publicHash = eth.hash.keccak256(publicKey);
  return eth.account.toChecksum('0x' + publicHash.slice(-40));
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
  this.web3 = new Web3( new Web3.providers.HttpProvider(this.endpoint() + '/' + options.infuraToken) );

  this.address = options.address;

  return this;
};

EthereumWallet.fromOptions = function fromOptions(options) {
  return new EthereumWallet().fromOptions(options);
};

EthereumWallet.prototype.load = async function load() {
  if (this.loaded) {
    return;
  }

  this.loaded = true;

  return this;
};

EthereumWallet.load = function load(options) {
  return EthereumWallet.fromOptions(options).load();
};

EthereumWallet.prototype.getBalance = async function getBalance() {
  return await this.web3.eth.getBalance(this.address);
};

EthereumWallet.prototype.prepareTransaction = async function createTransaction(to, value, fee) {
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
    tx.gasPrice = fee / tx.gas;
  }

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
