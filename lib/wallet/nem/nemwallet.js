'use strict';

const assert = require('assert');
const BN = require('bn.js');
const BigNumber = require('bignumber.js');

const { default: Nem } = require('nem-sdk');
const eddsa = require('elliptic').eddsa('ed25519');
const { Buffer } = require('buffer');

class NemWallet {
  constructor() {
    this.network = null;
    this.address = null;
    this.publicKey = null;
    this.endpoint = null;
  }
  
  static address(publicKey, network) {
    return Nem.model.address.toAddress(publicKey, NemWallet.networkId(network));
  }
	
	static networkId(network) {
		switch (network) {
      case NemWallet.Testnet:
			return Nem.model.network.data.testnet.id;
      case NemWallet.Mainnet:
			return Nem.model.network.data.mainnet.id;
		}
	}
  
  fromOptions(options) {
    this.network = options.network || NemWallet.Mainnet;
    this.publicKey = Buffer.from(eddsa.encodePoint(options.point)).toString('hex');
    this.address = NemWallet.address(this.publicKey, this.network);
    
    // should somehow depend on options.endpoint
		switch (this.network) {
      case NemWallet.Testnet:
			this.endpoint = Nem.model.objects.create("endpoint")(
				Nem.model.nodes.defaultTestnet,
				Nem.model.nodes.defaultPort
			);
			break;
      case NemWallet.Mainnet:
			this.endpoint = Nem.model.objects.create("endpoint")(
				Nem.model.nodes.defaultMainnet,
				Nem.model.nodes.defaultPort
			);
			break;
		}
    
    return this;
  }
  
  static fromOptions(options) {
    return new NemWallet().fromOptions(options);
  }
  
  verifyAddress(address) {
    return Nem.model.address.isValid(address);
  }
  
  async getBalance() {
    const data = await Nem.com.requests.account.data(this.endpoint, this.address);
    
    return {
      confirmed: new BN(data.account.balance),
      unconfirmed: new BN(data.account.balance)
    };
  }

  async getTransactions(page) {
    if (page !== 1) {
      return [];
    }

    const txs = await this.fetchTransactionList();

    return txs.map((tx) => {
      let type = 'In';

      if (tx.sender.toLowerCase() === this.address.toLowerCase()) {
        type = 'Out';
      }

      if (tx.sender === tx.recipient) {
        type = 'Self';
      }

      return {
        type: type,
        from:  tx.sender,
        to: tx.recipient,
        amount: this.toInternal(new BigNumber(tx.amount)),
        fee: new BN(tx.fee),
        confirmed: true,
        time: tx.timeStamp,
        hash: tx.id
      }
    });
  }

  async fetchTransactionList() {
    const response = await Nem.com.requests.account.transactions.all(this.endpoint, this.address);
    let transactions = [];
    response.data.forEach(tx => {
        let tx_type = undefined
        if (tx.transaction.type == 257 && tx.transaction.mosaics) {
            tx_type = 257
            if (tx.transaction.recipient != this.address) {
                let type = 'comission_mosaic_transfer';
                const transaction = {
                    recipient: tx.transaction.recipient,
                    sender: this.address,
                    timeStamp: tx.transaction.timeStamp,
                    fee: tx.transaction.fee,
                    amount: 0,
                    type: type,
                    comment: 'Comission for mosaic transfer'
                };
                transactions.push(transaction);
            }
        }
        if (tx.transaction.type == 8193) {
            tx_type = 8193
            let type = 'create_namespace';
            let parent = tx.transaction.parent + '.'
            if (parent == 'null.') parent = ''
            const transaction = {
                recipient: undefined,
                sender: this.address,
                timeStamp: tx.transaction.timeStamp,
                fee: tx.transaction.fee,
                amount: (tx.transaction.rentalFee / 1000000).toFixed(6),
                type: type,
                comment: 'Create namespace ' + parent + tx.transaction.newPart
            };
            transactions.push(transaction);
        }
        if (tx.transaction.type == 16385) {
            tx_type = 16385
            let type = 'create_mosaic';
            let mosaic = tx.transaction.mosaicDefinition.id
            const transaction = {
                recipient: undefined,
                sender: this.address,
                timeStamp: tx.transaction.timeStamp,
                fee: tx.transaction.fee,
                amount: (tx.transaction.creationFee / 1000000).toFixed(6),
                type: type,
                comment: 'Create mosaic ' + mosaic.namespaceId + ':' + mosaic.name
            };
            transactions.push(transaction);
        }
        if (tx.transaction.type == 257 && !tx.transaction.mosaics) {
            tx_type = 257
            let type = 'outgoing';
            let sender = this.address;
            if (tx.transaction.recipient == this.address) {
                type = 'incoming';
                sender = NemWallet.address(tx.transaction.signer, this.network);
            }
            const transaction = {
                id: tx.meta.id,
                recipient: tx.transaction.recipient,
                sender: sender,
                timeStamp: tx.transaction.timeStamp,
                fee: tx.transaction.fee,
                amount: (tx.transaction.amount / 1000000).toFixed(6),
                type: type,
                comment: 'XEM Transfer ' + type
            };
            transactions.push(transaction);
        }
        if (!tx_type) {
            let type = undefined;
            let sender = undefined;
            if (tx.transaction.signer) {
                sender = NemWallet.address(tx.transaction.signer, this.network);
            }
            let amount = 0;
            if (parseInt(tx.transaction.amount)) amount = parseInt(tx.transaction.amount)
            const transaction = {
                recipient: tx.transaction.recipient,
                sender: sender,
                timeStamp: tx.transaction.timeStamp,
                fee: tx.transaction.fee,
                amount: (amount / 1000000).toFixed(6),
                type: type,
                comment: 'Undefined transaction type'
            }
            transactions.push(transaction);
        }
    });
    return transactions;
  }
  
  async prepareTransaction(transaction, to, value, fee) {
    const construct = function(senderPublicKey, recipientCompressedKey, amount, message, msgFee, due, mosaics, mosaicsFee, network, manualFee) {
      const timeStamp = Nem.utils.helpers.createNEMTimeStamp();
      const version = mosaics ? Nem.model.network.getVersion(2, network) : Nem.model.network.getVersion(1, network);
      const data = Nem.model.objects.create("commonTransactionPart")(Nem.model.transactionTypes.transfer, senderPublicKey, timeStamp, due, version);
      const fee = mosaics ? mosaicsFee : Nem.model.fees.currentFeeFactor * Nem.model.fees.calculateMinimum(amount / 1000000);
      const totalFee = manualFee ? manualFee.toNumber() : Math.floor((msgFee + fee) * 1000000);
      const custom = {
        'recipient': recipientCompressedKey.toUpperCase().replace(/-/g, ''),
        'amount': amount,
        'fee': totalFee,
        'message': message,
        'mosaics': mosaics
      };
      return Nem.utils.helpers.extendObj(data, custom);
    };
    
    const prepare = function(publicKey, tx, network, fee){
      assert(!tx.isMultisig);
      
      const actualSender = publicKey;
      const recipientCompressedKey = tx.recipient.toString();
      const amount = Math.round(tx.amount * 1000000);
      const message = Nem.model.transactions.prepareMessage(null, tx);
      const msgFee = Nem.model.fees.calculateMessage(message, false);
      const due = network === Nem.model.network.data.testnet.id ? 60 : 24 * 60;
      const mosaics = null;
      const mosaicsFee = null;
      return construct(actualSender, recipientCompressedKey, amount, message, msgFee, due, mosaics, mosaicsFee, network, fee);
    };
    
    const transferTransaction = Nem.model.objects.create("transferTransaction")(to, this.fromInternal(value).toNumber());
    
    const transactionEntity = prepare(this.publicKey, transferTransaction, NemWallet.networkId(this.network), fee);
    
    return await transaction.fromOptions(transactionEntity);
  }

  async estimateTransaction(to, value) {
    return 1;
  }
  
  async sendSignedTransaction(blob) {
    await Nem.com.requests.transaction.announce(this.endpoint, JSON.stringify(blob));
  }
  
  fromInternal(value) {
    return new BigNumber(value.toString()).div(1000000);
  }
  
  toInternal(value) {
    return new BN(value.times(1000000).toFixed(0));
  }
}

NemWallet.Mainnet = 'main';
NemWallet.Testnet = 'testnet';

module.exports = {
  NemWallet
};
