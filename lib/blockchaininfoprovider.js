const EventEmitter = require('events');
const request = require('request-promise-native');

function BlockchainInfoProvider(options) {
  if(!(this instanceof BlockchainInfoProvider))
    return new BlockchainInfoProvider(options);

  EventEmitter.call(this);

  this.network = BlockchainInfoProvider.Testnet;

  if(options) {
    this.fromOptions(options);
  }
}

BlockchainInfoProvider.Mainnet = 'main';
BlockchainInfoProvider.Testnet = 'testnet';

Object.setPrototypeOf(BlockchainInfoProvider.prototype, EventEmitter.prototype);

BlockchainInfoProvider.prototype.fromOptions = function fromOptions(options) {
  this.network = options.network;
  return this;
};

BlockchainInfoProvider.fromOptions = function fromOptions(options) {
  return new BlockchainInfoProvider().fromOptions(options);
};

BlockchainInfoProvider.prototype.endpoint = function endpoint() {
  if(this.network === BlockchainInfoProvider.Mainnet) {
    return 'https://blockchain.info';
  } else {
    return 'https://testnet.blockchain.info';
  }
};

BlockchainInfoProvider.prototype.pullTransactions = async function pullTransactions(address) {
  const endpoint = this.endpoint();
  const limit = 50;
  let page = 0;

  let body = null;
  do {
     body = await request.get({
      uri: endpoint + '/rawaddr/' + address,
      json: true,
      qs: {
        limit: limit,
        offset: page*limit
      }
    });

    for (let tx of body.txs) {
      const confirmed = typeof tx.block_height !== 'undefined' && tx.block_height !== null;

      const meta = confirmed ? {
        hash: tx.hash, // illegal, but who cares
        height: tx.block_height,
        time: tx.time
      } : null;

      this.emit('transaction', tx.hash, meta);
    }
    page++;
  } while (body.n_tx > page*limit);
};

BlockchainInfoProvider.prototype.pullRawTransaction = async function pullRawTransaction(hash) {
  const endpoint = this.endpoint();

  return await request.get({
    uri: endpoint + '/rawtx/' + hash,
    json: true,
    qs: {
      format: 'hex'
    }
  });
};

BlockchainInfoProvider.prototype.pushTransaction = async function pushTransaction(hex) {
  const endpoint = this.endpoint();

  await request.post({
    uri: endpoint + '/pushtx',
    form:  {
      tx: hex
    }
  });
};

module.exports = BlockchainInfoProvider;
