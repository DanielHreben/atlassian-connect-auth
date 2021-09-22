import { generateKeyPairSync, KeyObject } from 'crypto';

function exportToString(k: KeyObject): string {
  return k.export({ format: 'pem', type: 'pkcs1' }).toString('hex');
}

export function generateTestAsymmetricKeys(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

  return {
    privateKey: exportToString(privateKey),
    publicKey: exportToString(publicKey),
  };
}
