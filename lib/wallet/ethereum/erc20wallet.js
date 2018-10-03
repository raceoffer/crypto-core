'use strict';

const abi = require('human-standard-token-abi');
const eth = require('eth-lib');
const Web3 = require('web3');
const BN = require('bn.js');
const BigNumber = require('bignumber.js');

const { EtherscanProvider } = require("../../provider/etherscanprovider");

class ERC20Wallet {
  constructor() {
    this.network = null;
    this.address = null;
    this.contractAddress = null;
    this.decimals = null;

    this.web3 = null;

    this.contract = null;

    this.etherscanProvider = null;
  }

  static address(point) {
    const publicKey = '0x' + point.encode('hex', false).slice(2);
    const publicHash = eth.hash.keccak256(publicKey);
    return eth.account.toChecksum('0x' + publicHash.slice(-40));
  }

  fromOptions(options) {
    this.network = options.network || ERC20Wallet.Mainnet;
    this.address = ERC20Wallet.address(options.point);
    this.contractAddress = options.contractAddress;
    this.decimals = options.decimals || 18;
    this.endpoint = options.endpoint;

    this.web3 = new Web3( new Web3.providers.HttpProvider(this.endpoint) );

    this.contract = new this.web3.eth.Contract(abi, this.contractAddress);

    this.etherscanProvider = EtherscanProvider.fromOptions({
      endpoint: this.network == EthereumWallet.Mainnet ? 'https://api.etherscan.io' : 'https://api-rinkeby.etherscan.io',
      apikey: 'YourApiKeyToken'
    });

    return this;
  }

  static fromOptions(options) {
    return new ERC20Wallet().fromOptions(options);
  }

  verifyAddress(address) {
    return Web3.utils.isAddress(address);
  }

  async getBalance() {
    const balance =  await this.contract.methods.balanceOf(this.address).call();
    return {
      confirmed: new BN(balance),
      unconfirmed: new BN(balance)
    };
  }

  async prepareTransaction(transaction, to, value, fee) {
    const [chainId, gasPrice, nonce] = await Promise.all([
      this.web3.eth.net.getId(),
      this.web3.eth.getGasPrice(),
      this.web3.eth.getTransactionCount(this.address)
    ]);

    const data = this.contract.methods.transfer(to, value.toString()).encodeABI();

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
      tx.gasPrice = fee.div(new BN(tx.gas)).toNumber();
    }

    return await transaction.fromOptions(tx, true);
  }

  async estimateTransaction(to, value) {
    const [chainId, gasPrice, nonce] = await Promise.all([
      this.web3.eth.net.getId(),
      this.web3.eth.getGasPrice(),
      this.web3.eth.getTransactionCount(this.address)
    ]);

    const data = this.contract.methods.transfer(to, value.toString()).encodeABI();

    const tx = {
      chainId: chainId,
      gasPrice: gasPrice,
      nonce: nonce,
      from: this.address,
      to: this.contractAddress,
      data: data
    };

    return await this.web3.eth.estimateGas(tx);
  }

  async sendSignedTransaction(raw) {
    await this.web3.eth.sendSignedTransaction(raw);
  }

  fromInternal(value) {
    return new BigNumber(value).div(new BigNumber(10).pow(this.decimals)).toNumber();
  }

  toInternal(value) {
    return new BN(new BigNumber(value).times(new BigNumber(10).pow(this.decimals)).toString(16), 16);
  }

  async getTransactions(from, to) {
    const offset = to - from + 1;
    const page = Math.ceil(from / offset);

    const txs = await this.etherscanProvider.getTokenTransactions(this.address, this.contractAddress, offset, page);

    return txs.map(tx => {

      let amount = new BN(tx.value);
      let type = 'In';

      if (tx.from === this.address.toLowerCase()) {
        amount.add(new BN(tx.gasUsed));
        type = 'Out';
      }

      if (tx.from === tx.to) {
        amount = new BN(tx.gasUsed);
      }

      return {
        type: type,
        from: tx.from,
        to: tx.to,
        amount: amount,
        confirmed: tx.blockNumber > 0,
        time: tx.timeStamp
      };
    });
  }
}

ERC20Wallet.Mainnet = 'main';
ERC20Wallet.Testnet = 'testnet';

module.exports = {
  ERC20Wallet
};
