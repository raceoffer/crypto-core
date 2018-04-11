const InsightProvider = require('../../provider/insightprovider');
const BitcoinCashTransaction = require('../../transaction/bitcore/bitcoincashtransaction');

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

BitcoinCashWallet.prototype.createTransaction = async function(to, value, fee) {
  const rawUTXO = await this.provider.getUTXO(this.address);

  const utxo = rawUTXO.map(raw => {
    return {
      txId: raw.txid,
      outputIndex: raw.vout,
      script: raw.scriptPubKey,
      satoshis: raw.satoshis
    }
  });

  return BitcoinCashTransaction.fromOptions({
    network: this.network,
    utxo: utxo,
    address: to,
    value: value,
    from: this.address,
    fee: fee
  });
};

BitcoinCashWallet.prototype.transactionFromJSON = function(json) {
  return BitcoinCashTransaction.fromJSON(json);
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
