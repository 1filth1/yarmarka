'use strict';

// Run from the functions directory after ADC is configured:
//   GOOGLE_APPLICATION_CREDENTIALS=/secure/path/service-account.json npm run set-admin -- FIREBASE_AUTH_UID
// Never commit the service-account JSON file.
const { initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');

async function main() {
  const uid = process.argv[2];
  if (!uid) {
    throw new Error('Usage: npm run set-admin -- FIREBASE_AUTH_UID');
  }

  initializeApp();
  const auth = getAuth();
  const user = await auth.getUser(uid);
  const existing = user.customClaims || {};
  await auth.setCustomUserClaims(uid, { ...existing, role: 'admin' });
  process.stdout.write(`Administrator claim assigned to UID ${uid}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
