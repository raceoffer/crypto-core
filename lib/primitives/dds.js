'use strict';

const assert = require("assert");
const web3 = require('web3');
const etherscan = require('etherscan-api');

export class DDS {
  constructor() {
    this.web3 = null;
    this.etherscan = null;
    this.network = DDS.Testnet;
  }

  endpoint() {
    switch(this.network) {
    case DDS.Mainnet:
      return 'https://mainnet.infura.io';
      break;
    case DDS.Testnet:
      return 'https://rinkeby.infura.io';
      break;
    default:
      return null;
    }
  };

  fromOptions(options) {
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

  static fromOptions(options) {
    return new DDS().fromOptions(options);
  }

  getAddress(secret) {
    return this.accountFromSecret(secret);
  }

  createAccount() {
    return DDS.Account.fromOptions({ account: this.web3.eth.accounts.create() });
  }

  accountFromSecret(secret) {
    return DDS.Account.fromOptions({ account: this.web3.eth.accounts.privateKeyToAccount(secret) });
  }

  async getBalance(account) {
    return await this.web3.eth.getBalance(account.address);
  }

  fromWei(balance, type) {
    return this.web3.utils.fromWei(balance, type);
  }

  toWei(balance, type) {
    return this.web3.utils.toWei(balance, type);
  }

  async estimateStoreGas(options) {
    assert(options.id, 'Id is required');
    assert(Buffer.isBuffer(options.data), 'Data must be a buffer');
    assert(options.account, 'Account is required');

    const account = options.account;
    const userAddress = this.getAddress(options.secret);

    const gas = await this.web3.eth.estimateGas({to: userAddress.address, from: account.address, data: '0x' + options.data.toString('hex') });
    return Math.round(1.1 * gas);
  }

  async store(options) {
    assert(options.id, 'Id is required');
    assert(Buffer.isBuffer(options.data), 'Data must be a buffer');
    assert(options.account, 'Account is required');

    const account = options.account;
    const userAddress = this.getAddress(options.secret);
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
  }

  async getTransactions(address) {
    return (await this.etherscan.account.txlist(address, 0, 'latest', 'asc')).result;
  }

  async count(secret) {
    const address = this.getAddress(secret).address;
    const transactions = await this.getTransactions(address);
    return transactions.length;
  }

  async exists(secret) {
    return (await this.count()) > 0;
  }

  async read(secret, index) {
    const address = this.getAddress(secret).address;
    const transactions = await this.getTransactions(address);
    return Buffer.from(transactions[index]['input'].slice(2), 'hex');
  }
}

DDS.Mainnet = 'main';
DDS.Testnet = 'testnet';

DDS.Account = class {
  constructor() {
    this.account = null;
    this.address = null;
  }

  fromOptions(options) {
    assert(options.account, 'Account is required');

    this.account = options.account;
    this.address = this.account.address;

    return this;
  }

  static fromOptions(options) {
    return new DDS.Account().fromOptions(options);
  }
};
