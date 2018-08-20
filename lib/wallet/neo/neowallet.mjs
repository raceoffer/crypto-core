import Neon from '@cityofzion/neon-js';
import BN from 'bn.js';

export class NeoWallet {
  constructor() {
    this.network = null;
    this.address = null;
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
}

NeoWallet.Mainnet = 'main';
NeoWallet.Testnet = 'testnet';