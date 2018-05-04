function BitcoreWallet() {
  this.network = null;
  this.address = null;
  this.provider = null;
}

BitcoreWallet.prototype.getBalance = async function() {
  return await this.provider.getBalance(this.address);
};

BitcoreWallet.prototype.getTransactions = async function() {
  const txs = await this.provider.getTransactions(this.address);

  return txs.map(tx => {
    const inputs = tx.inputs.map(input => {
      return {
        address: input.address,
        value: this.toInternal(input.value)
      }
    });
    const outputs = tx.outputs.map(output => {
      return {
        address: output.address,
        value: this.toInternal(output.value)
      }
    });

    const deficit = inputs
      .filter(input => input.address === this.address)
      .reduce((sum, input) => sum + input.value, 0);

    const proficit = outputs
      .filter(output => output.address === this.address)
      .reduce((sum, output) => sum + output.value, 0);

    if (proficit > deficit) {
      return {
        type: 'In',
        from: inputs.filter(input => input.address !== this.address).map(input => input.address)[0] || this.address,
        to: this.address,
        amount: proficit - deficit,
        confirmed: tx.blockHeight > 0,
        time: tx.time
      }
    } else {
      return {
        type: 'Out',
        from: this.address,
        to: outputs.filter(output => output.address !== this.address).map(output => output.address)[0] || this.address,
        amount: deficit - proficit,
        confirmed: tx.blockHeight > 0,
        time: tx.time
      }
    }
  });
};

BitcoreWallet.prototype.prepareTransaction = async function(transaction, to, value, fee) {
  const rawUTXO = await this.provider.getUTXO(this.address);

  const utxo = rawUTXO.map(raw => {
    return {
      txId: raw.txid,
      outputIndex: raw.vout,
      script: raw.scriptPubKey,
      satoshis: raw.satoshis
    }
  });

  return await transaction.fromOptions({
    network: this.network,
    utxo: utxo,
    address: to,
    value: value,
    from: this.address,
    fee: fee
  });
};

BitcoreWallet.prototype.sendSignedTransaction = async function(raw) {
  return this.provider.pushTransaction(raw);
};

module.exports = BitcoreWallet;
