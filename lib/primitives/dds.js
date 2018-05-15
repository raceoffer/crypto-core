const assert = require("assert");
const web3 = require('web3');
const etherscan = require('etherscan-api');
const utils = require('../utils');
const keychain = require('./keychain');

function DDS() {
  this.web3 = null;
  this.etherscan = null;
  this.network = DDS.Testnet;
}

DDS.Mainnet = 'main';
DDS.Testnet = 'testnet';

DDS.Account = function () {
  this.account = null;
  this.address = null;
};

DDS.Account.prototype.fromOptions = function fromOptions(options) {
  assert(options.account, 'Account is required');

  this.account = options.account;
  this.address = this.account.address;

  return this;
};

DDS.Account.fromOptions = function fromOptions(options) {
  return new DDS.Account().fromOptions(options);
};

DDS.prototype.endpoint = function endpoint() {
  if(this.network === DDS.Mainnet) {
    return 'https://mainnet.infura.io';
  } else {
    return 'https://rinkeby.infura.io';
  }
};

DDS.prototype.fromOptions = function fromOptions(options) {
  if (options.network) {
    this.network = options.network;
  }

  if (options.endpoint) {
    this.web3 = new web3( new web3.providers.HttpProvider(options.endpoint) );
  } else {
    this.web3 = new web3( new web3.providers.HttpProvider(this.endpoint() + '/' + options.infuraToken) );
  }

  this.etherscan = etherscan.init('YourApiKey', DDS.Mainnet === this.network ? null : 'rinkeby');
  return this;
}

DDS.prototype.getAddress = function (secret) {
  return this.accountFromSecret(secret);
}

DDS.prototype.createAccount = function createAccount() {
  return DDS.Account.fromOptions({ account: this.web3.eth.accounts.create() });
};

DDS.prototype.accountFromSecret = function accountFromSecret(secret) {
  return DDS.Account.fromOptions({ account: this.web3.eth.accounts.privateKeyToAccount(secret) });
};

DDS.fromOptions = function fromOptions(options) {
  return new DDS().fromOptions(options);
};

DDS.prototype.getBalance = async function getBalance(account) {
  return this.web3.eth.getBalance(account.address);
};

DDS.prototype.fromWei = function fromWei(balance, type) {
  return this.web3.utils.fromWei(balance, type);
};

DDS.prototype.toWei = function fromWei(balance, type) {
  return this.web3.utils.toWei(balance, type);
};

DDS.prototype.estimateStoreGas = async function estimateStoreGas(options) {
  assert(options.id, 'Id is required');
  assert(Buffer.isBuffer(options.data), 'Data must be a buffer');
  assert(options.account, 'Account is required');

  const account = options.account;
  const userAddress = await this.getAddress(options.secret);

  const gas = await this.web3.eth.estimateGas({to: userAddress.address, from: account.address, data: '0x' + options.data.toString('hex') });
  return Math.round(1.1 * gas);
};

DDS.prototype.store = async function (options) {
  assert(options.id, 'Id is required');
  assert(Buffer.isBuffer(options.data), 'Data must be a buffer');
  assert(options.account, 'Account is required');

  const account = options.account;
  const userAddress = await this.getAddress(options.secret);
  const gas = await this.web3.eth.estimateGas({to: userAddress.address, from: account.address, data: '0x' + options.data.toString('hex') });
  assert(gas < 1000000, "To much gas needed");

  const tx = {
    from: account.address,
    to: userAddress.address,
    gas: Math.round(1.05 * gas),
    data: '0x' + options.data.toString('hex')
  };

  if(options.gasPrice) {
    tx.gasPrice = options.gasPrice;
  }

  const signed = await account.account.signTransaction(tx);

  return await this.web3.eth.sendSignedTransaction(signed.rawTransaction);
};

DDS.prototype.getTransactions = async function(address) {
  try {
    return (await this.etherscan.account.txlist(address, 0, 'latest', 'asc')).result;
  } catch(e) {
    if (e == 'No transactions found') {
      return [];
    } else {
      throw e;
    }
  }
};

DDS.prototype.exists = async function (secret) {
  const address = this.getAddress(secret).address;
  const transactions = await this.getTransactions(address);
  return transactions && transactions.length > 0;
};

DDS.prototype.count = async function (secret) {
  const address = this.getAddress(secret).address;
  const transactions = await this.getTransactions(address);
  return transactions.length;
};

DDS.prototype.read = async function (secret, index) {
  const address = this.getAddress(secret).address;
  const transactions = await this.getTransactions(address);
  return Buffer.from(transactions[index]['input'].slice(2), 'hex');
};

module.exports = DDS;
