const elliptic = require('elliptic');

const Curve = {};
Curve[Curve.secp256k1 = 0] = 'secp256k1';
Curve[Curve.ed25519 = 1] = 'ed25519';
Curve[Curve.p256 = 2] = 'p256';

const curves = {
  [ Curve.secp256k1 ]: elliptic.ec('secp256k1'),
  [ Curve.ed25519 ]: elliptic.eddsa('ed25519'),
  [ Curve.p256 ]: elliptic.ec('p256')
};

function matchCurve(curve) {
  return curves[curve];
}

module.exports = {
  Curve,
  matchCurve
};