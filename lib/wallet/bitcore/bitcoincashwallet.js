const InsightProvider = require('../../provider/insightprovider');

const bitcoincashjs = require('bitcoincashjs');

function BitcoinCashWallet() {
  this.network = null;
  this.address = null;
  this.provider = null;
}

BitcoinCashWallet.address = function(key, network) {
  return new bitcoincashjs.PublicKey(
    new bitcoincashjs.crypto.Point(
      bitcoincashjs.crypto.BN.fromString(key.x.toString(16), 16),
      bitcoincashjs.crypto.BN.fromString(key.y.toString(16), 16),
      true
    ), {
      network: network === 'main' ? 'livenet' : 'testnet'
    }).toAddress().toString();
};

BitcoinCashWallet.Mainnet = 'main';
BitcoinCashWallet.Testnet = 'testnet';

BitcoinCashWallet.prototype.fromOptions = function(options) {
  this.network = options.network || BitcoinCashWallet.Mainnet;
  this.address = BitcoinCashWallet.address(options.key, this.network);

  let endpoint = null;
  switch (this.network) {
    case BitcoinCashWallet.Mainnet:
      endpoint = 'https://bch.blockdozer.com/insight-api';
      break;
    case BitcoinCashWallet.Testnet:
      endpoint = 'https://tbch.blockdozer.com/insight-api';
      break;
  }

  this.provider = InsightProvider.fromOptions({
    endpoint: endpoint
  });

  return this;
};

BitcoinCashWallet.fromOptions = function(options) {
  return new BitcoinCashWallet().fromOptions(options);
};

BitcoinCashWallet.prototype.getBalance = async function() {
  return await this.provider.getBalance(this.address);
};

BitcoinCashWallet.prototype.getTransactions = async function() {
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
        amount: this.fromInternal(proficit - deficit),
        confirmed: tx.blockHeight > 0,
        time: tx.time
      }
    } else {
      return {
        type: 'Out',
        from: this.address,
        to: outputs.filter(output => output.address !== this.address).map(output => output.address)[0] || this.address,
        amount: this.fromInternal(deficit - proficit),
        confirmed: tx.blockHeight > 0,
        time: tx.time
      }
    }
  });
};

BitcoinCashWallet.prototype.prepareTransaction = async function(transaction, to, value, fee) {
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

BitcoinCashWallet.prototype.sendSignedTransaction = async function(raw) {
  return this.provider.pushTransaction(raw);
};

BitcoinCashWallet.prototype.fromInternal = function(balance) {
  return bitcoincashjs.Unit.fromSatoshis(balance).toBTC();
};

BitcoinCashWallet.prototype.toInternal = function(balance) {
  return bitcoincashjs.Unit.fromBTC(balance).toSatoshis();
};

module.exports = BitcoinCashWallet;
