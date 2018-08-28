import Neon from '@cityofzion/neon-js';
import BN from 'bn.js';
import axios from 'axios'

export class NeoWallet {
  constructor() {
    this.network = null;
    this.address = null;
    this.assetId = "c56f33fc6ecfcd0c225c4ab356fee59390af8560be0e930faebe74a6daff7c9b";
  }

  static address(point) {
    const publicKey = Neon.wallet.getPublicKeyEncoded(point.encode('hex', false));
    const scriptHash = Neon.wallet.getScriptHashFromPublicKey(publicKey);

    return Neon.wallet.getAddressFromScriptHash(scriptHash);
  }
  
  static networkName(network) {
    return network === NeoWallet.Mainnet ? 'MainNet' : 'TestNet';
  }

  fromOptions(options) {
    this.network = options.network || NeoWallet.Mainnet;
    this.address = NeoWallet.address(options.point);
    this.endpoint = options.endpoint;

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

    if (data.assets.NEO !== undefined) {
      confirmed = parseFloat(data.assets.NEO.balance);
      unconfirmed = parseFloat(data.assets.NEO.balance) + data.assets.NEO.unconfirmed.reduce(function (balance, value) {
        return parseFloat(balance) + parseFloat(value['value']);
      }, 0);
    }

    return {
      confirmed: this.toInternal(confirmed),
      unconfirmed: this.toInternal(unconfirmed)
    };
  }

  async prepareTransaction(transaction, to, value, fee) {

    const intent = Neon.api.makeIntent({NEO: this.fromInternal(value)}, to);

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

    return await transaction.fromOptions(config);
  }

  async sendSignedTransaction(raw) {
    raw.tx.outputs.forEach(function(item) {
      item.value = parseFloat(item.value);
    });

    return await Neon.api.sendTx(raw);
  }

  fromInternal(value) {
    return value.toNumber();
  }

  toInternal(value) {
    return new BN(value);
  }

  async getTransactions(from, to) {
    const apiEndpoint = Neon.api.neoscan.getAPIEndpoint(
      NeoWallet.networkName(this.network)
    );

    let page = 1;

    const firstPage = await this.getTransactionHistory(apiEndpoint, this.address, page);

    let promises = [];

    for (page++; page <= firstPage.total_pages; page++) {
      promises.push(this.getTransactionHistory(apiEndpoint, this.address, page));
    }

    return Promise.all(promises)
      .then((txs) => {
        return txs.map(function(tx) {
          return tx.entries;
        });
      }).then((txs) => {
        return [].concat
          .apply(firstPage.entries, txs)
          .filter(
            tx => tx.asset === this.assetId
        ).map(tx => {
          return {
            type: (tx.address_from === this.address) ? 'Out' : 'In',
            from:  tx.address_from,
            to: tx.address_to,
            amount: tx.amount,
            confirmed: tx.block_height > 0,
            time: tx.time
          };
        }).slice(from, to);
      })
      .catch((e) => {
        return [];
      });
  }

  async getTransactionHistory(apiEndpoint, address, page) {
    return axios
      .get(apiEndpoint + '/v1/get_address_abstracts/' + address + '/' + page)
      .then(response => {
        return response.data;
      })
      .catch((e) => {
      });
  }
}

NeoWallet.Mainnet = 'main';
NeoWallet.Testnet = 'testnet';