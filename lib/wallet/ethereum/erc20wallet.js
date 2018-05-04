const abi = require('human-standard-token-abi');
const eth = require('eth-lib');
const Web3 = require('web3');

function ERC20Wallet() {
  this.network = null;
  this.address = null;
  this.contractAddress = null;
  this.decimals = null;

  this.web3 = null;

  this.contract = null;
}

ERC20Wallet.address = function(key) {
  const publicKey = '0x' + key.encode('hex', false).slice(2);
  const publicHash = eth.hash.keccak256(publicKey);
  return eth.account.toChecksum('0x' + publicHash.slice(-40));
};

ERC20Wallet.Mainnet = 'main';
ERC20Wallet.Testnet = 'testnet';

ERC20Wallet.prototype.fromOptions = function(options) {
  this.network = options.network || ERC20Wallet.Mainnet;
  this.address = ERC20Wallet.address(options.key);
  this.contractAddress = options.contractAddress;
  this.decimals = options.decimals || 18;
  this.endpoint = options.endpoint;

  this.web3 = new Web3( new Web3.providers.HttpProvider(this.endpoint) );

  this.contract = new this.web3.eth.Contract(abi, this.contractAddress);

  return this;
};

ERC20Wallet.fromOptions = function(options) {
  return new ERC20Wallet().fromOptions(options);
};

ERC20Wallet.prototype.getBalance = async function() {
  const balance =  await this.contract.methods.balanceOf(this.address).call();
  return {
    confirmed: balance,
    unconfirmed: balance
  };
};

ERC20Wallet.prototype.prepareTransaction = async function(transaction, to, value, fee) {
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
    tx.gasPrice = (fee / tx.gas).toString();
  }

  return await transaction.fromOptions(tx, true);
};

ERC20Wallet.prototype.sendSignedTransaction = async function(raw) {
  await this.web3.eth.sendSignedTransaction(raw);
};

ERC20Wallet.prototype.fromInternal = function(balance) {
  return balance / Math.pow(10, this.decimals);
};

ERC20Wallet.prototype.toInternal = function(balance) {
  return Math.floor(balance * Math.pow(10, this.decimals));
};

module.exports = ERC20Wallet;
