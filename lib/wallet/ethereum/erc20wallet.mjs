'use strict';

import abi from 'human-standard-token-abi';
import eth from 'eth-lib';
import Web3 from 'web3';
import BN from 'bn.js';

import BigNumber from 'bignumber.js';

export class ERC20Wallet {
  constructor() {
    this.network = null;
    this.address = null;
    this.contractAddress = null;
    this.decimals = null;

    this.web3 = null;

    this.contract = null;
  }

  static address(key) {
    const publicKey = '0x' + key.encode('hex', false).slice(2);
    const publicHash = eth.hash.keccak256(publicKey);
    return eth.account.toChecksum('0x' + publicHash.slice(-40));
  }

  fromOptions(options) {
    this.network = options.network || ERC20Wallet.Mainnet;
    this.address = ERC20Wallet.address(options.key);
    this.contractAddress = options.contractAddress;
    this.decimals = options.decimals || 18;
    this.endpoint = options.endpoint;

    this.web3 = new Web3( new Web3.providers.HttpProvider(this.endpoint) );

    this.contract = new this.web3.eth.Contract(abi, this.contractAddress);

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
      tx.gasPrice = fee.div(new BN(tx.gas)).toNumber();
    }

    return await transaction.fromOptions(tx, true);
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
}

ERC20Wallet.Mainnet = 'main';
ERC20Wallet.Testnet = 'testnet';