const abi = require('human-standard-token-abi');
const eth = require('eth-lib');
const Web3 = require('web3');

function ERC20Wallet() {
  this.loaded = false;
  this.contractAddress = null;
  this.contract = null;

  this.network = null;
  this.web3 = null;
  this.balance = 0;

  this.decimals = 18;
}

ERC20Wallet.formatPublic = function(key) {
  return '0x' + key.encode('hex', false).slice(2);
};

ERC20Wallet.formatPrivate = function(key) {
  return '0x' + key.toString(16);
};

ERC20Wallet.address = function(key) {
  const publicKey = this.formatPublic(key);
  const publicHash = eth.hash.keccak256(publicKey);
  return eth.account.toChecksum('0x' + publicHash.slice(-40));
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
  this.web3 = new Web3( new Web3.providers.HttpProvider(this.endpoint() + '/' + options.infuraToken) );

  this.address = options.address;
  this.contractAddress = options.contractAddress;
  this.contract = new this.web3.eth.Contract(abi, this.contractAddress);

  return this;
};

ERC20Wallet.fromOptions = function fromOptions(options) {
  return new ERC20Wallet().fromOptions(options);
};

ERC20Wallet.prototype.load = async function load() {
  if (this.loaded) {
    return;
  }

  this.loaded = true;

  try {
    this.decimals = await this.contract.methods.decimals().call();
  } catch (ignored) {}

  return this;
};

ERC20Wallet.load = function load(options) {
  return ERC20Wallet.fromOptions(options).load();
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

  return tx;
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
