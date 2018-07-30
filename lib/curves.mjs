import elliptic from 'elliptic';

const curves = {
  secp256k1: elliptic.ec('secp256k1'),
  ed25519: elliptic.eddsa('ed25519'),
  p256: elliptic.ec('p256')
};

export function matchCurve(curve) {
  return curves[curve];
}