const EventEmitter = require('events');
const request = require('request-promise-native');

function InsightsProvider(options) {
  if(!(this instanceof InsightsProvider))
    return new InsightsProvider(options);

  EventEmitter.call(this);

  this.network = InsightsProvider.Testnet;

  if(options) {
    this.fromOptions(options);
  }
}

InsightsProvider.Mainnet = 'main';
InsightsProvider.Testnet = 'testnet';

InsightsProvider.bcoin = (typeof bcoin !== 'undefined') ? bcoin : null;

InsightsProvider.set = function (bcoin) {
  InsightsProvider.bcoin = bcoin;
  return InsightsProvider;
};

Object.setPrototypeOf(InsightsProvider.prototype, EventEmitter.prototype);

InsightsProvider.prototype.fromOptions = function fromOptions(options) {
  this.network = options.network;
  return this;
};

InsightsProvider.fromOptions = function fromOptions(options) {
  return new InsightsProvider().fromOptions(options);
};

InsightsProvider.prototype.endpoint = function endpoint() {
  if(this.network === InsightsProvider.Mainnet) {
    return 'https://bcc.blockdozer.com/insight-api';
  } else {
    return 'https://tbcc.blockdozer.com/insight-api';
  }
};

InsightsProvider.prototype.pullTransactions = async function pullTransactions(address) {
  const endpoint = this.endpoint();
  let page = 0;

  let body = null;
  do {
    const req = {
      uri: endpoint + '/txs/',
      json: true,
      qs: {
        address: address,
        page: page
      }
    };

    body = await request.get(req);

    for (let tx of body.txs) {
      const confirmed = typeof tx.blockheight !== 'undefined' && tx.blockheight !== null && tx.blockheight > -1;

      const meta = confirmed ? {
        hash: tx.txid, // illegal, but who cares
        height: tx.blockheight,
        time: tx.time
      } : null;

      this.emit('transaction', tx.txid, meta);
    }
    page++;
  } while (body.pagesTotal > page);
};

InsightsProvider.prototype.pullRawTransaction = async function pullRawTransaction(hash) {
  const endpoint = this.endpoint();

  const tx = await request.get({
    uri: endpoint + '/rawtx/' + hash,
    json: true
  });

  return tx.rawtx;
};

InsightsProvider.prototype.pushTransaction = async function pushTransaction(hex) {
  const endpoint = this.endpoint();

  await request.post({
    uri: endpoint + '/tx/send',
    json: true,
    form:  {
      rawtx: hex
    }
  });
};

module.exports = InsightsProvider;
