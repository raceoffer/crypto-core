'use strict';

const BN = require('bn.js');

class BitcoreWallet {
  constructor(Transaction) {
    this.network = null;
    this.address = null;
    this.provider = null;
    this.Transaction = Transaction;
  }

  async getBalance() {
    const balance = await this.provider.getBalance(this.address);
    return {
      confirmed: new BN(balance.confirmed),
      unconfirmed: new BN(balance.unconfirmed)
    };
  }

  async getTransactions(to, from) {
    const txs = await this.provider.getTransactions(this.address, to, from);

    return txs.map(tx => {
      const inputs = tx.inputs.map(input => {
        return {
          address: input.address,
          value: this.toInternal(input.value)
        };
      });
      const outputs = tx.outputs.map(output => {
        return {
          address: output.address,
          value: this.toInternal(output.value)
        };
      });

      const deficit = inputs
        .filter(input => input.address === this.address)
        .reduce((sum, input) => sum.add(input.value), new BN());

      const proficit = outputs
        .filter(output => output.address === this.address)
        .reduce((sum, output) => sum.add(output.value), new BN());

      if (proficit.gt(deficit)) {
        return {
          type: 'In',
          from: inputs.filter(input => input.address !== this.address).map(input => input.address)[0] || this.address,
          to: this.address,
          amount: proficit.sub(deficit),
          confirmed: tx.blockHeight > 0,
          time: tx.time,
          blockhash: tx.blockhash
        };
      } else {
        return {
          type: 'Out',
          from: this.address,
          to: outputs.filter(output => output.address !== this.address).map(output => output.address)[0] || this.address,
          amount: deficit.sub(proficit),
          confirmed: tx.blockHeight > 0,
          time: tx.time,
          blockhash: tx.blockhash
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
