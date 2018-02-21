const EventEmitter = require('events');

function WatchingWallet(options) {
  if(!(this instanceof WatchingWallet))
    return new WatchingWallet(options);

  EventEmitter.call(this);

  this.walletId  = 'main';
  this.wallet = null;
  this.accounts = [];
  this.loaded = false;

  if(options) {
    this.fromOptions(options);
  }
}

WatchingWallet.bcoin = (typeof bcoin !== 'undefined') ? bcoin : null;

WatchingWallet.set = function (bcoin) {
  WatchingWallet.bcoin = bcoin;
  return WatchingWallet;
};

WatchingWallet.prototype.fromOptions = function fromOptions(options) {
  if (!options.accounts) {
    options.accounts = [];
  }

  this.accounts = options.accounts;

  return this;
};

WatchingWallet.fromOptions = function fromOptions(db, options) {
  return new WatchingWallet(db).fromOptions(options);
};

Object.setPrototypeOf(WatchingWallet.prototype, EventEmitter.prototype);

WatchingWallet.prototype.load = async function load(db) {
  if (this.loaded) {
    return;
  }

  this.loaded = true;

  this.wallet = await db.ensure({
    id: this.walletId,
    watchOnly: true
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

WatchingWallet.prototype.addAccount = async function addAccount(account) {
  if(this.accounts.indexOf(account) === -1) {
    this.accounts.push(account);
  }

  if (this.loaded) {
    const name = account.name;
    const key = account.key;

    try {
      await this.wallet.ensureAccount({
        name: name
      });
    } catch (e) {
      console.log(e)
    }

    if (!await this.wallet.getPath(key.getHash('hex'))) {
      await this.wallet.importKey(name, key);
    }
  }
};

WatchingWallet.prototype.defaultAccountName = function defaultAccountName() {
  if (this.accounts.length > 0) {
    return this.accounts[0].name;
  }
  return null;
};

WatchingWallet.prototype.getPublicKey = function getPublicKey(accountName, enc) {
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

WatchingWallet.prototype.getAddress = function getAddress(accountName, enc) {
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

WatchingWallet.prototype.getBalance = async function getBalance(accountName) {
  if (!accountName) {
    accountName = this.defaultAccountName();
  }
  return await this.wallet.getBalance(accountName);
};

WatchingWallet.prototype.addRawTransaction = async function addRawTransaction(hex, meta) {
  const transaction = WatchingWallet.bcoin.tx.fromRaw(hex, 'hex');
  const block = ( meta && meta.hash ) ? new WatchingWallet.bcoin.wallet.records.BlockMeta(meta.hash, meta.height, meta.time) : null;
  await this.wallet.add(transaction, block);
};

WatchingWallet.prototype.getRawTransaction = async function getRawTransaction(hash) {
  const tx = await this.wallet.txdb.getTX(WatchingWallet.bcoin.util.revHex(hash));
  return tx ? tx.toRaw().toString('hex') : null;
};

WatchingWallet.prototype.getCoins = async function getCoins(accountName) {
  if (!accountName) {
    accountName = this.defaultAccountName();
  }
  return await this.wallet.getCoins(accountName);
};

WatchingWallet.prototype.getTransactions = async function getTransactions(accountName) {
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

WatchingWallet.prototype.fund = async function fund(mtx, options) {
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

module.exports = WatchingWallet;
