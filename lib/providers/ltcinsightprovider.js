const InsightsProvider = require('./insightprovider');

function LTCInsightsProvider() {
  InsightsProvider.call(this);
}

LTCInsightsProvider.prototype = Object.create(InsightsProvider.prototype);
LTCInsightsProvider.prototype.constructor = LTCInsightsProvider;

LTCInsightsProvider.prototype.fromOptions = function fromOptions(options) {
  switch (options.network) {
    case 'main':
      this.endpoint = 'https://insight.litecore.io/api';
      break;
    case 'testnet':
      this.endpoint = 'https://testnet.litecore.io/api';
      break;
  }

  return this;
};

LTCInsightsProvider.fromOptions = function fromOptions(options) {
  return new LTCInsightsProvider().fromOptions(options);
};

module.exports = LTCInsightsProvider;
