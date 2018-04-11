const request = require('request-promise-native');

function InsightsProvider() {
  this.endpoint = null;
}

InsightsProvider.prototype.fromOptions = function(options) {
  this.endpoint = options.endpoint;
  return this;
};

InsightsProvider.fromOptions = function(options) {
  return new InsightsProvider().fromOptions(options);
};

InsightsProvider.prototype.getBalance = async function(address) {
  const req = {
    uri: this.endpoint + '/addr/' + address,
    json: true,
    qs: {
      noTxList: 1,
    }
  };

  const body = await request.get(req);

  return {
    confirmed: body.balanceSat,
    unconfirmed: body.balanceSat + body.unconfirmedBalanceSat
  }
};

InsightsProvider.prototype.getUTXO = async function(address) {
  const req = {
    uri: this.endpoint + '/addr/' + address + '/utxo',
    json: true
  };

  return await request.get(req);
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
