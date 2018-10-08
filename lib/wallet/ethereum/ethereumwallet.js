'use strict';

const eth = require('eth-lib');
const Web3 = require('web3');
const BN = require('bn.js');
const BigNumber = require('bignumber.js');

const { EtherscanProvider } = require("../../provider/etherscanprovider");

class EthereumWallet {
  constructor() {
    this.network = null;
    this.address = null;

    this.web3 = null;
    this.etherscanProvider = null;
  }

  static address(point) {
    const publicKey = '0x' + point.encode('hex', false).slice(2);
    const publicHash = eth.hash.keccak256(publicKey);
    return eth.account.toChecksum('0x' + publicHash.slice(-40));
  }

  fromOptions(options) {
    this.network = options.network || EthereumWallet.Mainnet;
    this.address = EthereumWallet.address(options.point);
    this.endpoint = options.endpoint;

    this.web3 = new Web3( new Web3.providers.HttpProvider(this.endpoint) );
    this.etherscanProvider = EtherscanProvider.fromOptions({
      endpoint: this.network == EthereumWallet.Mainnet ? 'https://api.etherscan.io' : 'https://api-rinkeby.etherscan.io',
      apikey: 'YourApiKeyToken'
    });

    return this;
  }

  static fromOptions(options) {
    return new EthereumWallet().fromOptions(options);
  }

  verifyAddress(address) {
    return Web3.utils.isAddress(address);
  }

  async getBalance() {
    const balance = await this.web3.eth.getBalance(this.address);
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

    const tx = {
      gasPrice: gasPrice,
      nonce: nonce,
      from: this.address,
      value: value.toString(),
      to: to
    };

    tx.gas = await this.web3.eth.estimateGas(tx);

    if (fee) {
      tx.gasPrice = fee.div(new BN(tx.gas)).toNumber();
    }

    tx.chainId = chainId;

    return await transaction.fromOptions(tx, false);
  }

  async estimateTransaction(to, value) {
    const [gasPrice, nonce] = await Promise.all([
      this.web3.eth.getGasPrice(),
      this.web3.eth.getTransactionCount(this.address)
    ]);

    const tx = {
      gasPrice: gasPrice,
      nonce: nonce,
      from: this.address,
      value: value.toString(),
      to: to
    };

    return await this.web3.eth.estimateGas(tx);
  }

  async sendSignedTransaction(raw) {
    await this.web3.eth.sendSignedTransaction(raw);
  }

  fromInternal(value) {
    return new BigNumber(value.toString()).div(new BigNumber('1000000000000000000'));
  }

  toInternal(value) {
    return new BN(value.times(new BigNumber('1000000000000000000')).toFixed(0));
  }

  async getTransactions(page) {
    const txs = await this.etherscanProvider.getTransactions(this.address, 15, page);

    return txs.map((tx) => {
      let amount = new BN(tx.value);
      let fee = new BN(tx.gasUsed);

      let type = 'In';

      if (tx.from === this.address.toLowerCase()) {
        type = 'Out';
      }

      if (tx.from === tx.to) {
        type = 'Self';
      }

      return {
        type: type,
        from: tx.from,
        to: tx.to,
        amount: amount,
        fee: fee,
        confirmed: tx.blockNumber > 0,
        time: tx.timeStamp,
        hash: tx.hash
      };
    }).filter((tx, index, self) => {
      return self.findIndex((other) => other.hash === tx.hash) === index;
    });
  }
}

EthereumWallet.Mainnet = 'main';
EthereumWallet.Testnet = 'testnet';

module.exports = {
  EthereumWallet
};
