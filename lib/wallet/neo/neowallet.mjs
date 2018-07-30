import Neon from '@cityofzion/neon-js';

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

    const data = await Neon.api.neoscan.getBalance(this.network, this.address);

    let confirmed = 0;
    let unconfirmed = 0;

    if (data.assets.NEO !== undefined) {
      confirmed = parseFloat(data.assets.NEO.balance);
      unconfirmed = data.assets.NEO.unconfirmed.reduce(function (balance, value) {
        return parseFloat(balance) + parseFloat(value['value']);
      }, 0);
    }

    return {
      confirmed: confirmed.toFixed(8),
      unconfirmed: unconfirmed.toFixed(8)
    };
  }

  async prepareTransaction(transaction, to, value, fee) {

    const intent = Neon.api.makeIntent({NEO: value}, to);

    const config = {
      net: this.network,
      address: this.address,
      intents: intent,
      fees: fee
    }

    await Neon.api.fillUrl(config)
      .then(Neon.api.fillKeys)
      .then(Neon.api.fillBalance)
      .then(c => Neon.api.createTx(c, 'contract'));

    return await transaction.fromOptions(config);
  }

  async sendSignedTransaction(raw) {
    await Neon.api.sendTx(raw);
  }

  fromInternal(value) {
    return value;
  }

  toInternal(value) {
    return value;
  }
}

NeoWallet.Mainnet = 'MainNet';
NeoWallet.Testnet = 'TestNet';