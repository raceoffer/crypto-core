'use strict';

const request = require('request-promise-native');

class EtherscanProvider {
  constructor() {
    this.endpoint = null;
    this.apikey = null;
  }

  fromOptions(options) {
    this.endpoint = options.endpoint;
    this.apikey = options.apikey;
    return this;
  }

  static fromOptions(options) {
    return new EtherscanProvider().fromOptions(options);
  }

  getTransactions(address, pagesize, page, startblock, endblock, sort) {
    var qs = {
      module: 'account',
      action: 'txlist',
      address: address,
      page: page || 1,
      offset: pagesize || 10,
      startblock: startblock || 0,
      endblock: endblock || 'latest',
      sort: sort ||'desc',
      apikey: this.apikey
    };

    return this.getRequest(qs);
  }

  getTokenTransactions(address, contractaddress, pagesize, page, startblock, endblock, sort) {
    var qs = {
      module: 'account',
      action: 'tokentx',
      address: address,
      contractaddress: contractaddress,
      page: page || 1,
      offset: pagesize || 10,
      startblock: startblock || 0,
      endblock: endblock || 'latest',
      sort: sort ||'desc',
      apikey: this.apikey
    };

    return this.getRequest(qs);
  }

  getRequest(qs) {
    const req = {
      uri: this.endpoint + '/api',
      json: true,
      qs: qs
    };

    return new Promise(function(resolve, reject) {
      request.get(req).then(function(response) {
        if (response.status && response.status != 1) {
          return reject(response.message);
        }

        if (response.error) {
          var message = response.error;

          if(typeof response.error === 'object' && response.error.message){
            message = response.error.message;
          }

          return reject(new Error(message));
        }

        resolve(response.result);
      }).catch(function(error) {
        return reject(new Error(error));
      });

    });
  }
}

module.exports = {
  EtherscanProvider
};
