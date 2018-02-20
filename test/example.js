const fs = require('fs');
const assert = require('assert');

const bcoinLib = require('..');

const bcoin = bcoinLib.bcoin;

const cash = require('bitcoincashjs');

const WatchingWallet = bcoinLib.watchingWallet;
const InsightProvider = bcoinLib.insightProvider;
const BlockchainInfoProvider = bcoinLib.blockchainInfoProvider;
const CompoundKey = bcoinLib.compoundKey;
const KeyChain = bcoinLib.keyChain;
const Utils = bcoinLib.utils;
const Transaction = bcoinLib.transaction;
const BitcoinTransaction = bcoinLib.bitcoinTransaction;
const BitcoinCashTransaction = bcoinLib.bitcoinCashTransaction;

const DDS = bcoinLib.dds;

const network = 'testnet';

const factorTree = {
  type: 1,
  value: Buffer.from('1111', 'utf-8'),
  children: [{
    type: 0,
    value: Buffer.from('222', 'utf-8')
  }, {
    type: 0,
    value: Buffer.from('333', 'utf-8'),
    children: [{
      type: 4,
      value: Buffer.from('Secret', 'utf-8')
    }]
  }]
};

const expandRoute = [{
  type: 1,
  value: Buffer.from('1111', 'utf-8')
},{
  type: 0,
  value: Buffer.from('222', 'utf-8')
}];

const transformer = function(factor) {
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(factor.type, 0);

  return Utils.sha256(Buffer.concat([prefix, factor.value]));
};

const matchPredefinedRoute = function(forest, route) {
  let currentFactor = 0;
  let currentData = forest;
  let result = null;
  while (!result) {
    const requestedFactor = currentFactor < route.length ? route[currentFactor++] : null;
    if (!requestedFactor) {
      break;
    }

    const matchResult = Utils.matchPassphrase(currentData, requestedFactor);
    if (typeof matchResult.seed !== 'undefined') {
      result = matchResult.seed;
      break;
    }

    if (matchResult.subtexts.length < 1) {
      break;
    }

    currentData = matchResult.subtexts;
  }

  return result;
};

const compoundTest = async function () {
  bcoin.set(network);

  const dds = new DDS({
    infuraToken: 'DKG18gIcGSFXCxcpvkBm',
    network: 'testnet'
  });

  const initiatorId = Utils.sha256(Buffer.from('lammonaaf', 'utf-8')).toString('hex');

  let initiatorSeed = null;
  if (await dds.exists(initiatorId)) {
    const count = await dds.count(initiatorId);
    const initiatorDDSData = [];
    for(let i=0; i<count; ++i) {
      initiatorDDSData.push(await dds.read(initiatorId, i));
    }
    initiatorSeed = matchPredefinedRoute(initiatorDDSData, expandRoute.map(transformer));
    console.log('Initiator loaded seed from dds');
  } else {
    if (fs.existsSync('enc_initiator.seed')) {
      const initiatorFileData = fs.readFileSync('enc_initiator.seed');
      initiatorSeed = matchPredefinedRoute(Utils.tryUnpackMultiple(initiatorFileData), expandRoute.map(transformer));
      console.log('Initiator loaded seed fom file');
    } else {
      initiatorSeed = Utils.randomBytes(64);
      fs.writeFileSync('enc_initiator.seed', Utils.packMultiple([Utils.packTree(factorTree, transformer, initiatorSeed)]));
      console.log('Initiator generated seed');
    }

    const initiatorKeyChain = KeyChain.fromSeed(initiatorSeed);

    const initiatorAccount = dds.accountFromSecret(initiatorKeyChain.getAccountSecret(60,0));
    const balance = await dds.getBalance(initiatorAccount);

    console.log("Initiator", initiatorAccount.address, dds.fromWei(balance,"ether") ,"eth");

    if (balance > 0) {
      await dds.store({
        id: initiatorId,
        data: Utils.packTree(factorTree, transformer, initiatorSeed),
        gasPrice: dds.toWei('5', 'gwei'),
        account: initiatorAccount
      });
      console.log('Initiator saved seed');
    } else {
      console.log('Not enough funds for initiator');
    }
  }

  const verifierId = Utils.sha256(Buffer.from('dorian', 'utf-8')).toString('hex');

  let verifierSeed = null;
  if (await dds.exists(verifierId)) {
    const count = await dds.count(verifierId);
    const verifierDDSData = [];
    for(let i=0; i<count; ++i) {
      verifierDDSData.push(await dds.read(verifierId, i));
    }
    verifierSeed = matchPredefinedRoute(verifierDDSData, expandRoute.map(transformer));
    console.log('Verifier loaded seed from dds');
  } else {
    if (fs.existsSync('enc_verifier.seed')) {
      const verifierFileData = fs.readFileSync('enc_verifier.seed');
      verifierSeed = matchPredefinedRoute(Utils.tryUnpackMultiple(verifierFileData), expandRoute.map(transformer));
      console.log('Verifier loaded seed fom file');
    } else {
      verifierSeed = Utils.randomBytes(64);
      fs.writeFileSync('enc_verifier.seed', Utils.packMultiple([Utils.packTree(factorTree, transformer, verifierSeed)]));
      console.log('Verifier generated seed');
    }

    const verifierKeyChain = KeyChain.fromSeed(verifierSeed);

    const verifierAccount = dds.accountFromSecret(verifierKeyChain.getAccountSecret(60,0));
    const balance = await dds.getBalance(verifierAccount);

    console.log("Verifier", verifierAccount.address, dds.fromWei(balance,"ether") ,"eth");

    if (balance > 0) {
      await dds.store({
        id: verifierId,
        data: Utils.packTree(factorTree, transformer, verifierSeed),
        gasPrice: dds.toWei('5', 'gwei'),
        account: verifierAccount
      });
      console.log('Verifier saved seed');
    } else {
      console.log('Not enough funds for verifier');
    }
  }

  const initiatorKeyChain = KeyChain.fromSeed(initiatorSeed);
  const verifierKeyChain = KeyChain.fromSeed(verifierSeed);

  const bitcoinWallet = await bitcoinSync(initiatorKeyChain, verifierKeyChain);
  const bitcoinCashWallet = await bitcoinCashSync(initiatorKeyChain, verifierKeyChain);

  await new Promise(res => setTimeout(res, 5000));

  await bitcoinSend(bitcoinWallet, bitcoinWallet.wallet.getAddress('base58'), 10000);

  const publicKey = new cash.PublicKey(
    bitcoinCashWallet.wallet.getPublicKey(), {
      network: 'testnet'
    });

  await bitcoinCashSend(bitcoinCashWallet, publicKey.toAddress().toString(), 10000);

  console.log("OK");
};

const sync = async function (initiator, verifier) {
  //!--- Secret sharing with Pedersen commitment scheme and original proof of paillier encryption
  const initiatorProver = initiator.startInitialCommitment();
  const verifierProver = verifier.startInitialCommitment();

  // Step 1: creating commitments
  const initiatorCommitment = JSON.stringify(initiatorProver.getInitialCommitment());
  const verifierCommitment = JSON.stringify(verifierProver.getInitialCommitment());

  // Step 3: exchanging decommitments (a party sends its decommitment only after it has received other party's commitment)
  const initiatorDecommitment = JSON.stringify(initiatorProver.processInitialCommitment(JSON.parse(verifierCommitment)));
  const verifierDecommitment = JSON.stringify(verifierProver.processInitialCommitment(JSON.parse(initiatorCommitment)));

  // Step 4: decommiting
  const verifierVerifier = verifierProver.processInitialDecommitment(JSON.parse(initiatorDecommitment));
  const initiatorVerifier = initiatorProver.processInitialDecommitment(JSON.parse(verifierDecommitment));

  // Further steps: interactive proofs of knowledge
  const verifierVerifierCommitment = JSON.stringify(verifierVerifier.getCommitment());
  const initiatorProverCommitment = JSON.stringify(initiatorProver.processCommitment(JSON.parse(verifierVerifierCommitment)));
  const verifierVerifierDecommitment = JSON.stringify(verifierVerifier.processCommitment(JSON.parse(initiatorProverCommitment)));
  const initiatorProverDecommitment = JSON.stringify(initiatorProver.processDecommitment(JSON.parse(verifierVerifierDecommitment)));
  const verifierVerifiedData = verifierVerifier.processDecommitment(JSON.parse(initiatorProverDecommitment));
  verifier.finishInitialSync(verifierVerifiedData);

  const initiatorVerifierCommitment = JSON.stringify(initiatorVerifier.getCommitment());
  const verifierProverCommitment = JSON.stringify(verifierProver.processCommitment(JSON.parse(initiatorVerifierCommitment)));
  const initiatorVerifierDecommitment = JSON.stringify(initiatorVerifier.processCommitment(JSON.parse(verifierProverCommitment)));
  const verifierProverDecommitment = JSON.stringify(verifierProver.processDecommitment(JSON.parse(initiatorVerifierDecommitment)));
  const initiatorVerifiedData = initiatorVerifier.processDecommitment(JSON.parse(verifierProverDecommitment));
  initiator.finishInitialSync(initiatorVerifiedData);

  //!--- End sharing
};

const sign = async function (transaction, initiator, verifier) {
  const imapping = transaction.mapInputs(initiator);
  const ihashes = transaction.getHashes(imapping);

  const vmapping = transaction.mapInputs(verifier);
  const vhashes = transaction.getHashes(vmapping);

  const isigners = transaction.startSign(ihashes, imapping);
  const vsigners = transaction.startSign(vhashes, vmapping);

  const ientropyCommitments = transaction.createEntropyCommitments(isigners);
  const ventropyCommitments = transaction.createEntropyCommitments(vsigners);

  const ientropyDecommitments = transaction.processEntropyCommitments(isigners, ventropyCommitments);
  const ventropyDecommitments = transaction.processEntropyCommitments(vsigners, ientropyCommitments);

  transaction.processEntropyDecommitments(isigners, ventropyDecommitments);
  transaction.processEntropyDecommitments(vsigners, ientropyDecommitments);

  const ciphertexts = transaction.computeCiphertexts(vsigners);

  const rawSignatures = transaction.extractSignatures(isigners, ciphertexts);

  const signatures = transaction.normalizeSignatures(imapping, rawSignatures);

  transaction.applySignatures(signatures);
};

const bitcoinSync = async function (initiatorKeyChain, verifierKeyChain) {
  const initiatorKey = bcoin.keyring.fromPrivate(initiatorKeyChain.getAccountSecret(0, 0));
  const verifierKey  = bcoin.keyring.fromPrivate(verifierKeyChain.getAccountSecret(0, 0));

  const initiator = new CompoundKey({
    localPrivateKeyring: initiatorKey
  });

  const verifier = new CompoundKey({
    localPrivateKeyring: verifierKey
  });

  await sync(initiator, verifier);

  // Start: configuring a wallet

  const walletdb = new bcoin.walletdb({
    db: 'memory',
    location: network
  });

  await walletdb.open();

  // The wallet is intended to watch over the full public key
  const wallet = await new WatchingWallet({
    accounts: [{
      name: initiator.getCompoundKeyAddress('base58'),
      key: initiator.compoundPublicKeyring
    }]
  }).load(walletdb);

  console.log(wallet.getAddress('base58'));

  wallet.on('transaction',(tx) => {
    console.log(JSON.stringify(tx.toJSON()));
  });

  wallet.on('balance', (balance) => {
    console.log('Balance:', bcoin.amount.btc(balance.confirmed), '(', bcoin.amount.btc(balance.unconfirmed), ')');
  });

  // End: configuring a wallet

  // Displaying an initial (loaded from db) balance
  const balance = await wallet.getBalance();
  console.log('Balance:', bcoin.amount.btc(balance.confirmed), '(', bcoin.amount.btc(balance.unconfirmed), ')');

  const provider = new BlockchainInfoProvider({
    network: network
  });

  provider.on('transaction', async (hash, meta) => {
    let hex = await wallet.getRawTransaction(hash);
    if (!hex) {
      hex = await provider.pullRawTransaction(hash);
    }
    await wallet.addRawTransaction(hex, meta);
  });

  // Initiate update routine
  await provider.pullTransactions(wallet.getAddress('base58'));
  setInterval(async () => {
    await provider.pullTransactions(wallet.getAddress('base58'));
  },10000);

  // End: configuring a provider

  return {
    wallet,
    provider,
    initiator,
    verifier
  };
};

const bitcoinSend = async function (wallet, address, value) {
  const transaction = BitcoinTransaction.fromOptions({
    network: Transaction.Testnet
  });

  await transaction.prepare({
    wallet: wallet.wallet,
    address: address,
    value: value
  });

  const total = transaction.totalOutputs();

  await sign(transaction, wallet.initiator, wallet.verifier);

  assert(transaction.tx.verify());

  const raw = transaction.toRaw();

  await wallet.provider.pushTransaction(raw);
};

const bitcoinCashSync = async function (initiatorKeyChain, verifierKeyChain) {
  const initiatorKey = bcoin.keyring.fromPrivate(initiatorKeyChain.getAccountSecret(0, 0));
  const verifierKey  = bcoin.keyring.fromPrivate(verifierKeyChain.getAccountSecret(0, 0));

  const initiator = new CompoundKey({
    localPrivateKeyring: initiatorKey
  });

  const verifier = new CompoundKey({
    localPrivateKeyring: verifierKey
  });

  await sync(initiator, verifier);

  // Start: configuring a wallet

  const walletdb = new bcoin.walletdb({
    db: 'memory',
    location: network
  });

  await walletdb.open();

  // The wallet is intended to watch over the full public key
  const wallet = await new WatchingWallet({
    accounts: [{
      name: initiator.getCompoundKeyAddress('base58'),
      key: initiator.compoundPublicKeyring
    }]
  }).load(walletdb);

  console.log(wallet.getAddress('base58'));

  wallet.on('transaction',(tx) => {
    console.log(JSON.stringify(tx.toJSON()));
  });

  wallet.on('balance', (balance) => {
    console.log('Balance:', bcoin.amount.btc(balance.confirmed), '(', bcoin.amount.btc(balance.unconfirmed), ')');
  });

  // End: configuring a wallet

  // Displaying an initial (loaded from db) balance
  const balance = await wallet.getBalance();
  console.log('Balance:', bcoin.amount.btc(balance.confirmed), '(', bcoin.amount.btc(balance.unconfirmed), ')');

  const provider = new InsightProvider({
    network: network
  });

  provider.on('transaction', async (hash, meta) => {
    let hex = await wallet.getRawTransaction(hash);
    if (!hex) {
      hex = await provider.pullRawTransaction(hash);
    }
    await wallet.addRawTransaction(hex, meta);
  });

  // Initiate update routine
  await provider.pullTransactions(wallet.getAddress('base58'));
  setInterval(async () => {
    await provider.pullTransactions(wallet.getAddress('base58'));
  },10000);

  // End: configuring a provider

  return {
    wallet,
    provider,
    initiator,
    verifier
  };
};

const bitcoinCashSend = async function (wallet, address, value) {
  const transaction = BitcoinCashTransaction.fromOptions({
    network: Transaction.Testnet
  });

  await transaction.prepare({
    wallet: wallet.wallet,
    address: address,
    value: value
  });

  const total = transaction.totalOutputs();

  await sign(transaction, wallet.initiator, wallet.verifier);

  assert(transaction.tx.verify());

  const raw = transaction.toRaw();

  await wallet.provider.pushTransaction(raw);
};

(async () => {
  await compoundTest();
})().catch(e => console.log(e));
