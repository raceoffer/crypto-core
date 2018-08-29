'use strict';

import request from 'request-promise-native';

export class InsightProvider {
  constructor() {
    this.endpoint = null;
  }

  fromOptions(options) {
    this.endpoint = options.endpoint;
    return this;
  }

  static fromOptions(options) {
    return new InsightProvider().fromOptions(options);
  }

  async getBalance(address) {
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
    };
  }

  async getUTXO(address) {
    const req = {
      uri: this.endpoint + '/addr/' + address + '/utxo',
      json: true
    };

    return await request.get(req);
  }

  async getTransactions(address, to, from) {
      const req = {
        uri: this.endpoint + '/addrs/' + address + '/txs',
        json: true,
        qs: {
          from: from,
          to: to
        }
      };
  
      const body = await request.get(req);
  
      return body.items.map(tx => {
        return {
          inputs: tx.vin.map(vin => {
            return {
              address: vin.addr,
              value: vin.value
            };
          }),
          outputs: tx.vout.map(vout => {
            return {
              address: vout.scriptPubKey.addresses[0] || null,
              value: vout.value
            };
          }),
          time: tx.time,
          blockHeight: tx.blockheight
        };
      });
  
  }

  async pushTransaction(hex) {
    await request.post({
      uri: this.endpoint + '/tx/send',
      json: true,
      form:  {
        rawtx: hex
      }
    });
  }
}
