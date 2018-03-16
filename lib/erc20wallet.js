const EventEmitter = require('events');
const abi = require('human-standard-token-abi');

const EthereumTransaction = require('./ethereum/ethereumtransaction');

function ERC20Wallet(options) {
  if(!(this instanceof ERC20Wallet))
    return new ERC20Wallet(options);

  EventEmitter.call(this);

  this.loaded = false;
  this.contractAddress = null;
  this.contract = null;

  this.network = null;
  this.web3 = null;
  this.routineTimer = null;
  this.balance = 0;

  this.decimals = 0;

  if(options) {
    this.fromOptions(options);
  }
}

ERC20Wallet.web3 = (typeof web3 !== 'undefined') ? web3 : null;

ERC20Wallet.set = function (web3) {
  ERC20Wallet.web3 = web3;
  return ERC20Wallet;
};

ERC20Wallet.Mainnet = 'main';
ERC20Wallet.Testnet = 'testnet';

ERC20Wallet.prototype.endpoint = function endpoint() {
  if(this.network === ERC20Wallet.Mainnet) {
    return 'https://mainnet.infura.io';
  } else {
    return 'https://rinkeby.infura.io';
  }
};

ERC20Wallet.prototype.fromOptions = function fromOptions(options) {
  if (options.network) {
    this.network = options.network;
  }
  this.web3 = new ERC20Wallet.web3( new ERC20Wallet.web3.providers.HttpProvider(this.endpoint() + '/' + options.infuraToken) );

  this.address = options.address;
  this.contractAddress = options.contractAddress;
  this.contract = new this.web3.eth.Contract(abi, this.contractAddress);

  return this;
};

ERC20Wallet.fromOptions = function fromOptions(options) {
  return new ERC20Wallet().fromOptions(options);
};

Object.setPrototypeOf(ERC20Wallet.prototype, EventEmitter.prototype);

ERC20Wallet.prototype.load = async function load() {
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

  this.decimals = await this.contract.methods.decimals().call();

  return this;
};

ERC20Wallet.prototype.getBalance = async function getBalance() {
  return await this.contract.methods.balanceOf(this.address).call();
};

ERC20Wallet.prototype.createTransaction = async function createTransaction(to, value, fee) {
  const [chainId, gasPrice, nonce] = await Promise.all([
    this.web3.eth.net.getId(),
    this.web3.eth.getGasPrice(),
    this.web3.eth.getTransactionCount(this.address)
  ]);

  const data = this.contract.methods.transfer(to, value).encodeABI();

  const tx = {
    chainId: chainId,
    gasPrice: gasPrice,
    nonce: nonce,
    from: this.address,
    to: this.contractAddress,
    data: data
  };

  tx.gas = await this.web3.eth.estimateGas(tx);

  if (fee) {
    tx.gasPrice = fee / tx.gas;
  }

  return EthereumTransaction.fromOptions(tx);
};

ERC20Wallet.prototype.sendSignedTransaction = async function(raw) {
  await this.web3.eth.sendSignedTransaction(raw);
};

ERC20Wallet.prototype.fromUnits = function fromUnits(balance) {
  return balance / (Math.pow(10, this.decimals));
};

ERC20Wallet.prototype.toUnits = function toUnits(balance) {
  return balance * (Math.pow(10, this.decimals));
};

module.exports = ERC20Wallet;
