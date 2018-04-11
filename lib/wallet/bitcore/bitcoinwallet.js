const InsightProvider = require('../../provider/insightprovider');

const bitcore = require('bitcore-lib');

function BitcoinWallet() {
  this.network = null;
  this.address = null;
  this.provider = null;
}

BitcoinWallet.address = function(key, network) {
  return new bitcore.PublicKey(
    new bitcore.crypto.Point(
      bitcore.crypto.BN.fromString(key.x.toString(16), 16),
      bitcore.crypto.BN.fromString(key.y.toString(16), 16),
      true
    ), {
      network: network
    }).toAddress().toString();
};

BitcoinWallet.Mainnet = 'main';
BitcoinWallet.Testnet = 'testnet';

BitcoinWallet.prototype.fromOptions = function(options) {
  this.network = options.network || BitcoinWallet.Mainnet;
  this.address = BitcoinWallet.address(options.key, this.network);

  let endpoint = null;
  switch (this.network) {
    case BitcoinWallet.Mainnet:
      endpoint = 'https://insight.bitpay.com/api';
      break;
    case BitcoinWallet.Testnet:
      endpoint = 'https://test-insight.bitpay.com/api';
      break;
  }

  this.provider = InsightProvider.fromOptions({
    endpoint: endpoint
  });

  return this;
};

BitcoinWallet.fromOptions = function(options) {
  return new BitcoinWallet().fromOptions(options);
};

BitcoinWallet.prototype.getBalance = async function() {
  return await this.provider.getBalance(this.address);
};

BitcoinWallet.prototype.getTransactions = async function() {
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

BitcoinWallet.prototype.prepareTransaction = async function(transaction, to, value, fee) {
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

BitcoinWallet.prototype.sendSignedTransaction = async function(raw) {
  return this.provider.pushTransaction(raw);
};

BitcoinWallet.prototype.fromInternal = function(balance) {
  return bitcore.Unit.fromSatoshis(balance).toBTC();
};

BitcoinWallet.prototype.toInternal = function(balance) {
  return bitcore.Unit.fromBTC(balance).toSatoshis();
};

module.exports = BitcoinWallet;
