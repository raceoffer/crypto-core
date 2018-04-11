const InsightProvider = require('../../provider/insightprovider');
const LitecoinTransaction = require('../../transaction/bitcore/litecointransaction');

const litecore = require('litecore-lib');

function LitecoinWallet() {
  this.network = null;
  this.address = null;
  this.provider = null;
}

LitecoinWallet.address = function(key, network) {
  return new litecore.PublicKey(
    new litecore.crypto.Point(
      litecore.crypto.BN.fromString(key.x.toString(16), 16),
      litecore.crypto.BN.fromString(key.y.toString(16), 16),
      true
    ), {
      network: network === 'main' ? 'livenet' : 'testnet'
    }).toAddress().toString();
};

LitecoinWallet.Mainnet = 'main';
LitecoinWallet.Testnet = 'testnet';

LitecoinWallet.prototype.fromOptions = function(options) {
  this.network = options.network || LitecoinWallet.Mainnet;
  this.address = LitecoinWallet.address(options.key, this.network);

  let endpoint = null;
  switch (this.network) {
    case LitecoinWallet.Mainnet:
      endpoint = 'https://insight.litecore.io/api';
      break;
    case LitecoinWallet.Testnet:
      endpoint = 'https://testnet.litecore.io/api';
      break;
  }

  this.provider = InsightProvider.fromOptions({
    endpoint: endpoint
  });

  return this;
};

LitecoinWallet.fromOptions = function(options) {
  return new LitecoinWallet().fromOptions(options);
};

LitecoinWallet.prototype.getBalance = async function() {
  return await this.provider.getBalance(this.address);
};

LitecoinWallet.prototype.createTransaction = async function(to, value, fee) {
  const rawUTXO = await this.provider.getUTXO(this.address);

  const utxo = rawUTXO.map(raw => {
    return {
      txId: raw.txid,
      outputIndex: raw.vout,
      script: raw.scriptPubKey,
      satoshis: raw.satoshis
    }
  });

  return LitecoinTransaction.fromOptions({
    network: this.network,
    utxo: utxo,
    address: to,
    value: value,
    from: this.address,
    fee: fee
  });
};

LitecoinWallet.prototype.transactionFromJSON = function(json) {
  return LitecoinTransaction.fromJSON(json);
};

LitecoinWallet.prototype.sendSignedTransaction = async function(raw) {
  return this.provider.pushTransaction(raw);
};

LitecoinWallet.prototype.fromInternal = function(balance) {
  return litecore.Unit.fromSatoshis(balance).toBTC();
};

LitecoinWallet.prototype.toInternal = function(balance) {
  return litecore.Unit.fromBTC(balance).toSatoshis();
};

module.exports = LitecoinWallet;
