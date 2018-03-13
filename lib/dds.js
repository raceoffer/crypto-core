const assert = require("assert");

function DDS(options) {
  if(!(this instanceof DDS))
    return new DDS(options);

  this.web3 = null;
  this.contract = null;
  this.network = DDS.Testnet;

  if(options) {
    this.fromOptions(options);
  }
}

DDS.web3 = (typeof web3 !== 'undefined') ? web3 : null;

DDS.set = function (web3) {
  DDS.web3 = web3;
  return DDS;
};

DDS.Mainnet = 'main';
DDS.Testnet = 'testnet';

DDS.Account = function (options) {
  if(!(this instanceof DDS.Account))
    return new DDS.Account(options);

  this.account = null;
  this.address = null;

  if(options) {
    this.fromOptions(options);
  }
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

DDS.prototype.contractAddress = function contractAddress() {
  if(this.network === DDS.Mainnet) {
    return null;
  } else {
    return '0xa1d7D6d8E19B3952cb0e51812E5d8A16c2b2F971';
  }
};

DDS.prototype.fromOptions = function fromOptions(options) {
  if (options.network) {
    this.network = options.network;
  }

  if (options.endpoint) {
    this.web3 = new DDS.web3( new DDS.web3.providers.HttpProvider(options.endpoint) );
  } else {
    this.web3 = new DDS.web3( new DDS.web3.providers.HttpProvider(this.endpoint() + '/' + options.infuraToken) );
  }

  this.contract = new this.web3.eth.Contract([{
      "constant" : true,
      "inputs" : [{
        "name" : "id",
        "type" : "string"
      }],
      "name" : "count",
      "outputs" : [{
        "name" : "",
        "type" : "uint256"
      }],
      "payable" : false,
      "stateMutability" : "view",
      "type" : "function"
    },{
      "constant" : true,
      "inputs" : [{
        "name" : "id",
        "type" : "string"
      }],
      "name" : "exists",
      "outputs" : [{
        "name" : "",
        "type" : "bool"
      }],
      "payable" : false,
      "stateMutability" : "view",
      "type" : "function"
    },{
      "constant" : true,
      "inputs" : [{
        "name" : "id",
        "type" : "string"
      },{
        "name" : "n",
        "type" : "uint256"
      }],
      "name" : "read",
      "outputs" : [{
        "name" : "",
        "type" : "bytes"
      }],
      "payable" : false,
      "stateMutability" : "view",
      "type" : "function"
    },{
      "constant" : false,
      "inputs" : [{
        "name" : "id",
        "type" : "string"
      },{
        "name" : "data",
        "type" : "bytes"
      }],
      "name" : "store",
      "outputs" : [],
      "payable" : false,
      "stateMutability" : "nonpayable",
      "type" : "function"
    }],
    this.contractAddress());

  return this;
};

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

  const store = this.contract.methods.store(options.id, '0x' + options.data.toString('hex'));
  const gas = await store.estimateGas({ from: account.address });
  return Math.round(1.1 * gas);
};

DDS.prototype.store = async function (options) {
  assert(options.id, 'Id is required');
  assert(Buffer.isBuffer(options.data), 'Data must be a buffer');
  assert(options.account, 'Account is required');

  const account = options.account;

  const store = this.contract.methods.store(options.id, '0x' + options.data.toString('hex'));
  const gas = await store.estimateGas({ from: account.address });
  assert(gas < 1000000, "To much gas needed");

  const abi = store.encodeABI();

  const tx = {
    from: account.address,
    to: this.contract.options.address,
    gas: Math.round(1.05 * gas),
    data: abi
  };

  if(options.gasPrice) {
    tx.gasPrice = options.gasPrice;
  }

  const signed = await account.account.signTransaction(tx);

  return await this.web3.eth.sendSignedTransaction(signed.rawTransaction);
};

DDS.prototype.exists = async function (id) {
  return await this.contract.methods.exists(id).call();
};

DDS.prototype.count = async function (id) {
  return await this.contract.methods.count(id).call();
};

DDS.prototype.read = async function (id, index) {
  const stringData = await this.contract.methods.read(id, index).call();
  return Buffer.from(stringData.slice(2), 'hex');
};

module.exports = DDS;
