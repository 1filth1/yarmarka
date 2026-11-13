#!/usr/bin/env node
'use strict';

// Emulator-only bootstrap. Refuses to run unless both Auth and Firestore emulators are active.
const readline = require('node:readline');
const argon2 = require('argon2');
const { initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');

if (!process.env.FIREBASE_AUTH_EMULATOR_HOST || !process.env.FIRESTORE_EMULATOR_HOST) {
  throw new Error('Refusing to run: FIREBASE_AUTH_EMULATOR_HOST and FIRESTORE_EMULATOR_HOST must both be set.');
}
const projectId = process.env.GCLOUD_PROJECT || process.env.FIREBASE_PROJECT_ID;
if (!projectId || !projectId.startsWith('demo-')) {
  throw new Error('Use a demo project ID such as demo-yarmarka-test.');
}
const login = String(process.argv[2] || 'admin.test').trim().toLowerCase();
if (!/^[a-z0-9][a-z0-9._-]{2,39}$/.test(login)) throw new Error('Invalid login.');

function readPassword() {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY || !process.stdin.setRawMode) return reject(new Error('Run in an interactive terminal.'));
    process.stdout.write('Test admin password (min 14 chars): ');
    let value = '';
    const onData = (chunk) => {
      for (const ch of chunk.toString('utf8')) {
        if (ch === '\u0003') { process.stdin.setRawMode(false); reject(new Error('Cancelled.')); return; }
        if (ch === '\r' || ch === '\n') {
          process.stdin.setRawMode(false); process.stdin.pause(); process.stdin.removeListener('data', onData);
          process.stdout.write('\n'); resolve(value); return;
        }
        if (ch === '\u007f' || ch === '\b') value = value.slice(0, -1);
        else if (ch >= ' ') value += ch;
      }
    };
    process.stdin.setRawMode(true); process.stdin.resume(); process.stdin.on('data', onData);
  });
}

async function main() {
  const password = await readPassword();
  if (password.length < 14 || password.length > 256) throw new Error('Password must contain 14–256 characters.');
  initializeApp({ projectId });
  const auth = getAuth();
  const db = getFirestore();
  const user = await auth.createUser({ disabled: false });
  await auth.setCustomUserClaims(user.uid, { role: 'admin' });
  const passwordHash = await argon2.hash(password, {
    type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1
  });
  await db.collection('loginIndex').doc(login).create({
    uid: user.uid, role: 'admin', status: 'active', passwordHash,
    passwordHashVersion: 1, createdAt: FieldValue.serverTimestamp()
  });
  await db.collection('loginReservations').doc(login).set({
    uid: user.uid, status: 'active', updatedAt: FieldValue.serverTimestamp()
  });
  process.stdout.write('EMULATOR ADMIN READY: ' + login + ' (UID ' + user.uid + ')\n');
}
main().catch((error) => { process.stderr.write(error.message + '\n'); process.exitCode = 1; });
