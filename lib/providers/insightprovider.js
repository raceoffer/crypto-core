const EventEmitter = require('events');
const request = require('request-promise-native');

function InsightsProvider() {
  EventEmitter.call(this);

  this.endpoint = null;
}

Object.setPrototypeOf(InsightsProvider.prototype, EventEmitter.prototype);

InsightsProvider.prototype.fromOptions = function fromOptions(options) {
  this.endpoint = options.endpoint;
  return this;
};

InsightsProvider.fromOptions = function fromOptions(options) {
  return new InsightsProvider().fromOptions(options);
};

InsightsProvider.prototype.pullTransactions = async function pullTransactions(address) {
  let page = 0;

  let body = null;
  do {
    const req = {
      uri: this.endpoint + '/txs/',
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
  const tx = await request.get({
    uri: this.endpoint + '/rawtx/' + hash,
    json: true
  });

  return tx.rawtx;
};

InsightsProvider.prototype.pushTransaction = async function pushTransaction(hex) {
  await request.post({
    uri: this.endpoint + '/tx/send',
    json: true,
    form:  {
      rawtx: hex
    }
  });
};

module.exports = InsightsProvider;
