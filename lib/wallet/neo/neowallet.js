const Neon = require('@cityofzion/neon-js');
const BN = require('bn.js');
const axios = require('axios');

class NeoWallet {
  constructor() {
    this.network = null;
    this.address = null;
    this.assetId = null;
    this.assetName = null;
    this.decimals = null;
    this.publicKey = null;
  }

  static address(point) {
    const publicKey = Neon.wallet.getPublicKeyEncoded(point.encode('hex', false));
    const scriptHash = Neon.wallet.getScriptHashFromPublicKey(publicKey);

    return Neon.wallet.getAddressFromScriptHash(scriptHash);
  }
  
  static networkName(network) {
    return network === NeoWallet.Mainnet ? Neon.CONST.NEO_NETWORK.MAIN : Neon.CONST.NEO_NETWORK.TEST;
  }

  fromOptions(options) {
    this.network = options.network || NeoWallet.Mainnet;
    this.publicKey = options.point;
    this.address = NeoWallet.address(this.publicKey);
    this.endpoint = options.endpoint;

    const asset = options.asset || "c56f33fc6ecfcd0c225c4ab356fee59390af8560be0e930faebe74a6daff7c9b";
    const assetName = Neon.CONST.ASSETS[asset];

    if (assetName != undefined) {
      this.assetId = Neon.CONST.ASSET_ID[assetName];
      this.assetName = assetName;
    } else {
      this.assetId = asset;
    }

    this.decimals = options.decimals || 0;

    return this;
  }

  static fromOptions(options) {
    return new NeoWallet().fromOptions(options);
  }

  verifyAddress(address) {
    return Neon.wallet.isAddress(address);
  }

  async getBalance() {
    const data = await Neon.api.neoscan.getBalance(NeoWallet.networkName(this.network), this.address);

    let confirmed = 0;
    let unconfirmed = 0;

    const asset = data.assets[this.assetName];

    if (asset !== undefined) {
      confirmed = parseFloat(asset.balance);
      unconfirmed = parseFloat(asset.balance) + asset.unconfirmed.reduce(function (balance, value) {
        return parseFloat(balance) + parseFloat(value['value']);
      }, 0);
    }

    return {
      confirmed: this.toInternal(confirmed),
      unconfirmed: this.toInternal(unconfirmed)
    };
  }

  async prepareTransaction(transaction, to, value, fee) {
    let assetAmounts = {};
    assetAmounts[this.assetName] = this.fromInternal(value);

    const intent = Neon.api.makeIntent(assetAmounts, to);

    const config = {
      net: NeoWallet.networkName(this.network),
      address: this.address,
      intents: intent,
      fees: fee != undefined ? this.fromInternal(fee) : 0
    };

    await Neon.api.fillUrl(config)
      .then(Neon.api.fillKeys)
      .then(Neon.api.fillBalance)
      .then(c => Neon.api.createTx(c, 'contract'));

    config.tx.outputs.forEach(function(item) {
      item.value = parseFloat(item.value);
    });

    config.publicKey =  this.publicKey.encode('hex', false);

    return await transaction.fromOptions(config);
  }

  async estimateTransaction(to, value) {
    return 1;
  }

  async sendSignedTransaction(raw) {
    const config = {
      tx: new Neon.tx.Transaction(raw.tx),
      url: raw.url
    };

    config.tx.outputs.forEach(function(item) {
      item.value = parseFloat(item.value);
    });

    return await Neon.api.sendTx(config);
  }

  fromInternal(value) {
    return value.toNumber() / Math.pow(10, this.decimals);
  }

  toInternal(value) {
    return new BN(value * Math.pow(10, this.decimals));
  }

  async getTransactions(page) {
    const apiEndpoint = Neon.api.neoscan.getAPIEndpoint(
      NeoWallet.networkName(this.network)
    );

    const txs = await this.getTransactionHistory(apiEndpoint, this.address, page);

    return txs.entries.filter(
      tx => tx.asset === this.assetId
    ).map(tx => {
      let type = 'In';

      if (tx.address_from === this.address) {
        type = 'Out';
      }

      if (tx.address_from === tx.address_to) {
        type = 'Self';
      }

      return {
        type: type,
        from:  tx.address_from,
        to: tx.address_to,
        amount: this.toInternal(parseFloat(tx.amount)),
        fee: new BN(),
        confirmed: tx.block_height > 0,
        time: tx.time,
        hash: tx.txid
      };
    });
  }

  async getTransactionHistory(apiEndpoint, address, page) {
    return axios
      .get(apiEndpoint + '/v1/get_address_abstracts/' + address + '/' + page)
      .then(response => {
        return response.data;
      });
  }
}

NeoWallet.Mainnet = 'main';
NeoWallet.Testnet = 'testnet';

module.exports = {
  NeoWallet
};
