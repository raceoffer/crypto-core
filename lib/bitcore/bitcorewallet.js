const EventEmitter = require('events');
const bcoin = {
  keyring: require('bcoin/lib/primitives/keyring'),
  amount: require('bcoin/lib/btc/amount'),
  address: require('bcoin/lib/primitives/address'),
  walletdb: require('bcoin/lib/wallet/walletdb'),
  wallet: require('bcoin/lib/wallet/wallet'),
  records: require('bcoin/lib/wallet/records'),
  tx: require('bcoin/lib/primitives/tx'),
  util: require('bcoin/lib/utils/util')
};

function BitcoreWallet() {
  if(!(this instanceof BitcoreWallet))
    return new BitcoreWallet();

  EventEmitter.call(this);

  this.db = null;
  this.network = null;
  this.walletId  = 'main';
  this.wallet = null;
  this.accounts = [];
  this.loaded = false;
}

BitcoreWallet.prototype.fromOptions = function fromOptions(options) {
  if (!options.accounts) {
    options.accounts = [];
  }

  this.network = options.network;

  this.accounts = options.accounts.map(account => {
    return {
      name: account.name,
      key: bcoin.keyring.fromPublic(Buffer.from(account.key.encode(true, 'array')), this.network)
    }
  });

  return this;
};

BitcoreWallet.fromOptions = function fromOptions(options) {
  return new BitcoreWallet().fromOptions(options);
};

BitcoreWallet.toInternal = function(amount) {
  return bcoin.amount.fromBTC(amount).value;
};

BitcoreWallet.fromInternal = function(amount) {
  return bcoin.amount.btc(parseInt(amount));
};

BitcoreWallet.addressFromScript = function(script) {
  return bcoin.address.fromScript(script);
};

Object.setPrototypeOf(BitcoreWallet.prototype, EventEmitter.prototype);

BitcoreWallet.prototype.load = async function load() {
  this.db = new bcoin.walletdb({
    db: 'memory',
    network: this.network
  });

  await this.db.open();

  if (this.loaded) {
    return;
  }

  this.loaded = true;

  this.wallet = await this.db.ensure({
    id: this.walletId,
    watchOnly: true,
    network: this.network
  });

  this.wallet.on('tx',(tx)=>{
    this.emit('transaction',tx);
  });

  this.wallet.on('balance',async ()=>{
    let balance = await this.getBalance();
    this.emit('balance',balance);
  });

  for (let i=0; i<this.accounts.length; ++i) {
      await this.addAccount(this.accounts[i]);
  }

  return this;
};

BitcoreWallet.load = function load(options) {
  return BitcoreWallet.fromOptions(options).load();
};

BitcoreWallet.prototype.addAccount = async function addAccount(account) {
  if(this.accounts.indexOf(account) === -1) {
    this.accounts.push(account);
  }

  if (this.loaded) {
    const key = account.key;
    const name = account.name || key.getKeyAddress('base58');

    try {
      await this.wallet.ensureAccount({
        name: name,
        network: this.network
      });
    } catch (e) {
      console.log(e)
    }

    if (!await this.wallet.getPath(key.getHash('hex'))) {
      await this.wallet.importKey(name, key);
    }
  }
};

BitcoreWallet.prototype.defaultAccountName = function defaultAccountName() {
  if (this.accounts.length > 0) {
    return this.accounts[0].name;
  }
  return null;
};

BitcoreWallet.prototype.getPublicKey = function getPublicKey(accountName, enc) {
  if (accountName === 'base58' || accountName === 'hex') {
    enc = accountName;
    accountName = null;
  }

  if (!accountName) {
    accountName = this.defaultAccountName();
  }

  let accountKey = null;
  for (let i=0; i<this.accounts.length; ++i) {
    if (this.accounts[i].name === accountName) {
      accountKey = this.accounts[i].key;
    }
  }

  if (!accountKey) {
    return null;
  }

  return accountKey.getPublicKey(enc);
};

BitcoreWallet.prototype.getAddress = function getAddress(accountName, enc) {
  if (accountName === 'base58' || accountName === 'hex') {
    enc = accountName;
    accountName = null;
  }

  if (!accountName) {
    accountName = this.defaultAccountName();
  }

  let accountKey = null;
  for (let i=0; i<this.accounts.length; ++i) {
    if (this.accounts[i].name === accountName) {
      accountKey = this.accounts[i].key;
    }
  }

  if (!accountKey) {
    return null;
  }

  return accountKey.getKeyAddress(enc);
};

BitcoreWallet.prototype.getBalance = async function getBalance(accountName) {
  if (!accountName) {
    accountName = this.defaultAccountName();
  }
  return await this.wallet.getBalance(accountName);
};

BitcoreWallet.prototype.addRawTransaction = async function addRawTransaction(hex, meta) {
  const transaction = bcoin.tx.fromRaw(hex, 'hex');
  const block = ( meta && meta.hash ) ? new bcoin.records.BlockMeta(meta.hash, meta.height, meta.time) : null;
  await this.wallet.add(transaction, block);
};

BitcoreWallet.prototype.getRawTransaction = async function getRawTransaction(hash) {
  const tx = await this.wallet.txdb.getTX(bcoin.util.revHex(hash));
  return tx ? tx.toRaw().toString('hex') : null;
};

BitcoreWallet.prototype.getCoins = async function getCoins(accountName) {
  if (!accountName) {
    accountName = this.defaultAccountName();
  }
  return await this.wallet.getCoins(accountName);
};

BitcoreWallet.prototype.getTransactions = async function getTransactions(accountName) {
  if (!accountName) {
    accountName = this.defaultAccountName();
  }
  const records = await this.wallet.getHistory(accountName);
  return records.map(rec => {
    return {
      tx: rec.tx,
      meta: rec.height > -1 ? {
        hash: rec.block,
        height: rec.height,
        time: rec.time
      } : null
    }});
};

BitcoreWallet.prototype.fund = async function fund(mtx, options) {
  if (!options)
    options = {};

  if (!options.accountName) {
    options.accountName = this.defaultAccountName();
  }

  return await mtx.fund(await this.getCoins(options.accountName),{
    changeAddress: this.getAddress(options.accountName, 'base58'),
    subtractFee: options.subtractFee
  });
};

module.exports = BitcoreWallet;
