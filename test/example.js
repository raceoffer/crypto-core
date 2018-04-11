const fs = require('fs');
const assert = require('assert');

const CryptoCore = require('..');

const BitcoinWallet = CryptoCore.BitcoinWallet;
const BitcoinCashWallet = CryptoCore.BitcoinCashWallet;
const LitecoinWallet = CryptoCore.LitecoinWallet;
const EthereumWallet = CryptoCore.EthereumWallet;

const BitcoinTransaction = CryptoCore.BitcoinTransaction;
const BitcoinCashTransaction = CryptoCore.BitcoinCashTransaction;
const LitecoinTransaction = CryptoCore.LitecoinTransaction;
const EthereumTransaction = CryptoCore.EthereumTransaction;

const KeyChain = CryptoCore.KeyChain;
const CompoundKey = CryptoCore.CompoundKey;
const Utils = CryptoCore.Utils;
const DDS = CryptoCore.DDS;

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
  const dds = DDS.fromOptions({
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

  const paillierKeys = CompoundKey.generatePaillierKeys();

  const bitcoin = await walletSync(BitcoinWallet, initiatorKeyChain, verifierKeyChain, paillierKeys);
  const bitcoinCash = await walletSync(BitcoinCashWallet, initiatorKeyChain, verifierKeyChain, paillierKeys);
  const litecoin = await walletSync(LitecoinWallet, initiatorKeyChain, verifierKeyChain, paillierKeys);
  const ethereum = await walletSync(EthereumWallet, initiatorKeyChain, verifierKeyChain, paillierKeys);

  await send(BitcoinTransaction, bitcoin, bitcoin.wallet.address, 1000);
  await send(BitcoinCashTransaction, bitcoinCash, bitcoinCash.wallet.address, 1000);
  await send(LitecoinTransaction, litecoin, litecoin.wallet.address, 1000);
  await send(EthereumTransaction, ethereum, ethereum.wallet.address, 1000);

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

const sign = async function (Transaction, transaction, initiator, verifier) {
  const itransaction = transaction;
  const vtransaction = Transaction.fromJSON(transaction.toJSON());

  const imapping = itransaction.mapInputs(initiator);
  const ihashes = itransaction.getHashes(imapping);

  const vmapping = vtransaction.mapInputs(verifier);
  const vhashes = vtransaction.getHashes(vmapping);

  itransaction.startSign(ihashes, imapping);
  vtransaction.startSign(vhashes, vmapping);

  const ientropyCommitments = itransaction.createEntropyCommitments();
  const ventropyCommitments = vtransaction.createEntropyCommitments();

  const ientropyDecommitments = itransaction.processEntropyCommitments(ventropyCommitments);
  const ventropyDecommitments = vtransaction.processEntropyCommitments(ientropyCommitments);

  itransaction.processEntropyDecommitments(ventropyDecommitments);
  vtransaction.processEntropyDecommitments(ientropyDecommitments);

  const ciphertexts = vtransaction.computeCiphertexts();

  const rawSignatures = itransaction.extractSignatures(ciphertexts);

  const signatures = itransaction.normalizeSignatures(imapping, rawSignatures);

  itransaction.applySignatures(signatures);
};

const walletSync = async function (Wallet, initiatorKeyChain, verifierKeyChain, paillierKeys) {
  const initiatorKey = CompoundKey.keyFromSecret(initiatorKeyChain.getAccountSecret(0, 0));
  const verifierKey  = CompoundKey.keyFromSecret(verifierKeyChain.getAccountSecret(0, 0));

  const initiator = CompoundKey.fromOptions({
    localPrivateKey: initiatorKey,
    localPaillierKeys: paillierKeys
  });

  const verifier = CompoundKey.fromOptions({
    localPrivateKey: verifierKey,
    localPaillierKeys: paillierKeys
  });

  await sync(initiator, verifier);

  const wallet = Wallet.fromOptions({
    key: initiator.getCompoundPublicKey(),
    network: network
  });

  console.log(Wallet.prototype.constructor.name, 'address', wallet.address);

  const balance = await wallet.getBalance();
  console.log(Wallet.prototype.constructor.name, 'balance:', wallet.fromInternal(balance.confirmed), '(', wallet.fromInternal(balance.unconfirmed), ')');

  return {
    wallet,
    initiator,
    verifier
  };
};

const send = async function (Transaction, wallet, address, value) {
  const transaction = await wallet.wallet.prepareTransaction(new Transaction(), address, value);

  console.log(transaction.totalOutputs());

  await sign(Transaction, transaction, wallet.initiator, wallet.verifier);

  assert(transaction.verify());

  await wallet.wallet.sendSignedTransaction(transaction.toRaw());
};

(async () => {
  try {
    await compoundTest();
  } catch (e) {
    console.log(e);
  }
})();
