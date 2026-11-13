'use strict';

// Provision the first administrator only from a trusted machine.
// Usage: node scripts/provision-admin.js FIREBASE_AUTH_UID unique-login
// The password is read from stdin; do not pass it as a command-line argument.
// GOOGLE_APPLICATION_CREDENTIALS must point to a service-account key outside this repository.

const readline = require('node:readline');
const argon2 = require('argon2');
const { initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');

const uid = process.argv[2];
const login = String(process.argv[3] || '').trim().toLowerCase();

function readPassword() {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== 'function') {
      reject(new Error('Run this script in an interactive terminal so the password can be entered without echo.'));
      return;
    }
    process.stdout.write('Initial admin password (min 14 chars): ');
    let value = '';
    const onData = (chunk) => {
      const input = chunk.toString('utf8');
      for (const ch of input) {
        if (ch === '\\u0003') {
          process.stdin.setRawMode(false);
          process.stdin.pause();
          reject(new Error('Cancelled.'));
          return;
        }
        if (ch === '\\r' || ch === '\\n') {
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdin.removeListener('data', onData);
          process.stdout.write('\\n');
          resolve(value);
          return;
        }
        if (ch === '\\u007f' || ch === '\\b') value = value.slice(0, -1);
        else if (ch >= ' ') value += ch;
      }
    };
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on('data', onData);
  });
}

async function main() {
  if (!uid || !/^[a-z0-9][a-z0-9._-]{2,39}$/.test(login)) {
    throw new Error('Usage: node scripts/provision-admin.js FIREBASE_AUTH_UID unique-login');
  }
  const password = await readPassword();
  if (password.length < 14 || password.length > 256) {
    throw new Error('Password must contain 14–256 characters.');
  }

  initializeApp();
  const auth = getAuth();
  const db = getFirestore();
  const user = await auth.getUser(uid);
  const loginRef = db.collection('loginIndex').doc(login);
  const reservationRef = db.collection('loginReservations').doc(login);

  await db.runTransaction(async (tx) => {
    const existing = await tx.get(loginRef);
    const reservation = await tx.get(reservationRef);
    if (existing.exists || (reservation.exists && reservation.data().status === 'active')) {
      throw new Error('Login is already in use.');
    }
    const passwordHash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 19456,
      timeCost: 2,
      parallelism: 1
    });
    tx.create(loginRef, {
      uid: user.uid,
      role: 'admin',
      status: 'active',
      passwordHash,
      passwordHashVersion: 1,
      createdAt: FieldValue.serverTimestamp()
    });
    tx.set(reservationRef, {
      uid: user.uid,
      status: 'active',
      updatedAt: FieldValue.serverTimestamp()
    });
  });

  const existingClaims = user.customClaims || {};
  await auth.setCustomUserClaims(uid, { ...existingClaims, role: 'admin' });
  process.stdout.write('Administrator login provisioned. Store the login in the approved credential vault.\\n');
}

main().catch((error) => {
  process.stderr.write(error.message + '\\n');
  process.exitCode = 1;
});
