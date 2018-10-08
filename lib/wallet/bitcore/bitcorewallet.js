'use strict';

const BN = require('bn.js');
const BigNumber = require('bignumber.js');

class BitcoreWallet {
  constructor(Transaction) {
    this.network = null;
    this.address = null;
    this.provider = null;
    this.Transaction = Transaction;
  }

  fromInternal(value) {
    return new BigNumber(value.toString()).div(100000000);
  }

  toInternal(value) {
    return new BN(value.times(100000000).toFixed(0));
  }

  async getBalance() {
    const balance = await this.provider.getBalance(this.address);
    return {
      confirmed: new BN(balance.confirmed),
      unconfirmed: new BN(balance.unconfirmed)
    };
  }

  async getTransactions(page) {
    const txs = await this.provider.getTransactions(this.address, 15, page);

    return txs.map(tx => {
      const inputs = tx.inputs.map(input => {
        return {
          address: input.address,
          value: this.toInternal(new BigNumber(input.value))
        };
      });
      const outputs = tx.outputs.map(output => {
        return {
          address: output.address,
          value: this.toInternal(new BigNumber(output.value))
        };
      });

      const inputValue = inputs.reduce((sum, input) => sum.add(input.value), new BN());
      const outputValue = outputs.reduce((sum, output) => sum.add(output.value), new BN());

      const fee = inputValue.sub(outputValue);
      
      const proficit = outputs
        .filter(output => output.address === this.address)
        .reduce((sum, output) => sum.add(output.value), new BN());

      const deficit = outputs
        .filter(output => output.address !== this.address)
        .reduce((sum, output) => sum.add(output.value), new BN());

      if (inputs.every(input => input.address === this.address)) {
        if (outputs.every(output => output.address === this.address)) {
          return {
            type: 'Self',
            from: this.address,
            to: this.address,
            amount: outputs.length > 0 ? outputs[0].value : new BN(),
            fee: fee,
            confirmed: tx.blockHeight > 0,
            time: tx.time,
            hash: tx.hash
          };
        } else {
          return {
            type: 'Out',
            from: this.address,
            to: outputs.length > 0 ? outputs[0].address : '',
            amount: deficit,
            fee: fee,
            confirmed: tx.blockHeight > 0,
            time: tx.time,
            hash: tx.hash
          };
        }
      } else {
        return {
          type: 'In',
          from: inputs.filter(input => input.address !== this.address).map(input => input.address)[0] || '',
          to: this.address,
          amount: proficit,
          fee: fee,
          confirmed: tx.blockHeight > 0,
          time: tx.time,
          hash: tx.hash
        };
      }
    });
  }

  async prepareTransaction(transaction, to, value, fee) {
    const rawUTXO = await this.provider.getUTXO(this.address);

    const utxo = rawUTXO.map(raw => {
      return {
        txId: raw.txid,
        outputIndex: raw.vout,
        script: raw.scriptPubKey,
        satoshis: raw.satoshis
      };
    });

    return await transaction.fromOptions({
      network: this.network,
      utxo: utxo,
      address: to,
      value: value,
      from: this.address,
      fee: fee
    });
  }

  async estimateTransaction(to, value) {
    const rawUTXO = await this.provider.getUTXO(this.address);

    const utxo = rawUTXO.map(raw => {
      return {
        txId: raw.txid,
        outputIndex: raw.vout,
        script: raw.scriptPubKey,
        satoshis: raw.satoshis
      };
    });

    return new this.Transaction().from(utxo).to(to, value.toNumber()).change(this.address)._estimateSize();
  }

  async sendSignedTransaction(raw) {
    return this.provider.pushTransaction(raw);
  }
}

module.exports = {
  BitcoreWallet
};
