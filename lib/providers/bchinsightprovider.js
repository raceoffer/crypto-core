const InsightsProvider = require('./insightprovider');

function BCHInsightsProvider() {
  InsightsProvider.call(this);
}

BCHInsightsProvider.prototype = Object.create(InsightsProvider.prototype);
BCHInsightsProvider.prototype.constructor = BCHInsightsProvider;

BCHInsightsProvider.prototype.fromOptions = function fromOptions(options) {
  switch (options.network) {
    case 'main':
      this.endpoint = 'https://bcc.blockdozer.com/insight-api';
      break;
    case 'testnet':
      this.endpoint = 'https://tbcc.blockdozer.com/insight-api';
      break;
  }

  return this;
};

BCHInsightsProvider.fromOptions = function fromOptions(options) {
  return new BCHInsightsProvider().fromOptions(options);
};

module.exports = BCHInsightsProvider;
