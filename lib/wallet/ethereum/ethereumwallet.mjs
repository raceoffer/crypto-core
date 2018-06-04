'use strict';

import eth from 'eth-lib';
import Web3 from 'web3';
import unit from 'ethjs-unit';
import BN from 'bn.js';

export class EthereumWallet {
  constructor() {
    this.network = null;
    this.address = null;

    this.web3 = null;
  }

  static address(key) {
    const publicKey = '0x' + key.encode('hex', false).slice(2);
    const publicHash = eth.hash.keccak256(publicKey);
    return eth.account.toChecksum('0x' + publicHash.slice(-40));
  }

  fromOptions(options) {
    this.network = options.network || EthereumWallet.Mainnet;
    this.address = EthereumWallet.address(options.key);
    this.endpoint = options.endpoint;

    this.web3 = new Web3( new Web3.providers.HttpProvider(this.endpoint) );

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
      chainId: chainId,
      gasPrice: gasPrice,
      nonce: nonce,
      from: this.address,
      value: value,
      to: to
    };

    tx.gas = await this.web3.eth.estimateGas(tx);

    if (fee) {
      tx.gasPrice = fee.div(new BN(tx.gas)).toNumber();
    }

    return await transaction.fromOptions(tx, false);
  }

  async sendSignedTransaction(raw) {
    await this.web3.eth.sendSignedTransaction(raw);
  }

  fromInternal(value) {
    return parseFloat(unit.fromWei(value, 'ether'));
  }

  toInternal(value) {
    return unit.toWei(parseFloat(value).toFixed(18), 'ether');
  }
}

EthereumWallet.Mainnet = 'main';
EthereumWallet.Testnet = 'testnet';
