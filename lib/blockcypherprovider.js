const EventEmitter = require('events');
const request = require('request-promise-native');

function BlockCypherProvider(options) {
    if(!(this instanceof BlockCypherProvider))
        return new BlockCypherProvider(options);

    EventEmitter.call(this);

    if(options) {
        this.fromOptions(options);
    }
}

Object.setPrototypeOf(BlockCypherProvider.prototype, EventEmitter.prototype);

BlockCypherProvider.prototype.fromOptions = function fromOptions(options) {
    return this;
};

BlockCypherProvider.fromOptions = function fromOptions(options) {
    return new BlockCypherProvider().fromOptions(options);
};

BlockCypherProvider.prototype.pullTransactions = async function pullTransactions(address) {
    const body = await request.get({
        uri: 'https://api.blockcypher.com/v1/btc/test3/addrs/' + address + '/full',
        json: true,
        qs: {
            includeHex: true,
            token: '8c9599425ea0434fa79745c8aba418d7'
        }
    });
    for (let tx of body.txs) {
        this.emit('rawTransaction',tx.hex,{
            hash: tx.block_hash,
            height: tx.block_height,
            time: tx.confirmed
        });
    }
};

BlockCypherProvider.prototype.pushTransaction = async function pushTransaction(hex) {
    await request.post({
        uri: 'https://api.blockcypher.com/v1/btc/test3/txs/push',
        json: true,
        qs: {
            token: '8c9599425ea0434fa79745c8aba418d7'
        },
        body: {
            tx: hex
        }
    });
};

module.exports = BlockCypherProvider;
