const EventEmitter = require('events');
const request = require('request-promise-native');

function InsightsProviderLTC(options) {
    if(!(this instanceof InsightsProviderLTC))
        return new InsightsProviderLTC(options);

    EventEmitter.call(this);

    this.network = InsightsProviderLTC.Testnet;

    if(options) {
        this.fromOptions(options);
    }
}

InsightsProviderLTC.Mainnet = 'main';
InsightsProviderLTC.Testnet = 'testnet';

Object.setPrototypeOf(InsightsProviderLTC.prototype, EventEmitter.prototype);

InsightsProviderLTC.prototype.fromOptions = function fromOptions(options) {
    this.network = options.network;
    return this;
};

InsightsProviderLTC.fromOptions = function fromOptions(options) {
    return new InsightsProviderLTC().fromOptions(options);
};

InsightsProviderLTC.prototype.endpoint = function endpoint() {
    if(this.network === InsightsProviderLTC.Mainnet) {
        return 'https://insight.litecore.io/api';
    } else {
        return 'https://testnet.litecore.io/api';
    }
};

InsightsProviderLTC.prototype.pullTransactions = async function pullTransactions(address) {
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

InsightsProviderLTC.prototype.pullRawTransaction = async function pullRawTransaction(hash) {
    const endpoint = this.endpoint();

    const tx = await request.get({
        uri: endpoint + '/rawtx/' + hash,
        json: true
    });

    return tx.rawtx;
};

InsightsProviderLTC.prototype.pushTransaction = async function pushTransaction(hex) {
    const endpoint = this.endpoint();

    await request.post({
        uri: endpoint + '/tx/send',
        json: true,
        form:  {
            rawtx: hex
        }
    });
};

module.exports = InsightsProviderLTC;