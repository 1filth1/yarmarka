'use strict';

const crypto = require('node:crypto');
const argon2 = require('argon2');
const { initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore, FieldValue, Timestamp } = require('firebase-admin/firestore');
const { onCall, HttpsError } = require('firebase-functions/v2/https');
const logger = require('firebase-functions/logger');

initializeApp();
const db = getFirestore();

const REGION = 'us-central1';
const ARGON_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1
};
const APPLICATIONS = 'staffApplications';
const PROFILES = 'staffProfiles';
const LOGIN_INDEX = 'loginIndex';
const LOGIN_RESERVATIONS = 'loginReservations';
const RATE_LIMITS = 'authRateLimits';
const SECURITY_EVENTS = 'securityEvents';
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 10;
const ACTIVATION_TTL_MS = 24 * 60 * 60 * 1000;
const ACTIVATION_MAX_ATTEMPTS = 5;
const DUMMY_HASH_PROMISE = argon2.hash(
  'not-a-real-user-password-' + crypto.randomBytes(32).toString('hex'),
  ARGON_OPTIONS
);

function fail(code, message) {
  throw new HttpsError(code, message);
}

function requireString(value, field, min, max) {
  if (typeof value !== 'string') fail('invalid-argument', `Некорректное поле: ${field}`);
  const result = value.trim();
  if (result.length < min || result.length > max) {
    fail('invalid-argument', `Некорректная длина поля: ${field}`);
  }
  return result;
}

function normalizeLogin(value) {
  const login = requireString(value, 'login', 3, 40).toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{2,39}$/.test(login)) {
    fail('invalid-argument', 'Логин: 3–40 символов, латиница, цифры, точка, дефис или подчёркивание.');
  }
  return login;
}

function validatePassword(value) {
  if (typeof value !== 'string' || value.length < 14 || value.length > 256) {
    fail('invalid-argument', 'Пароль должен содержать от 14 до 256 символов.');
  }
  if (/^(.)\1+$/.test(value) || /^(password|qwerty|123456|letmein)/i.test(value)) {
    fail('invalid-argument', 'Выберите более стойкий пароль.');
  }
  return value;
}

function requireAdmin(request) {
  if (!request.auth || request.auth.token.role !== 'admin') {
    fail('permission-denied', 'Недостаточно прав.');
  }
  return request.auth.uid;
}

function clientIp(request) {
  const forwarded = request.rawRequest && request.rawRequest.headers
    ? request.rawRequest.headers['x-forwarded-for']
    : null;
  const candidate = (typeof forwarded === 'string' ? forwarded.split(',')[0] : null)
    || (request.rawRequest && request.rawRequest.ip)
    || 'unknown';
  return String(candidate).slice(0, 64);
}

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function randomCode() {
  return crypto.randomBytes(24).toString('base64url');
}

async function applyRateLimit(scope, key, maxAttempts, windowMs) {
  const docId = hash(`${scope}:${key}`);
  const ref = db.collection(RATE_LIMITS).doc(docId);
  const now = Date.now();

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const data = snap.exists ? snap.data() : {};
    const windowStart = data.windowStartAt ? data.windowStartAt.toMillis() : 0;
    const attempts = windowStart && now - windowStart < windowMs ? (data.attempts || 0) : 0;
    const start = attempts ? windowStart : now;

    if (attempts >= maxAttempts) {
      fail('resource-exhausted', 'Слишком много попыток. Попробуйте позже.');
    }

    tx.set(ref, {
      scope,
      attempts: attempts + 1,
      windowStartAt: Timestamp.fromMillis(start),
      expiresAt: Timestamp.fromMillis(now + windowMs * 2)
    });
  });
}

async function audit(action, actorUid, metadata = {}) {
  await db.collection(SECURITY_EVENTS).add({
    action,
    actorUid: actorUid || null,
    metadata,
    createdAt: FieldValue.serverTimestamp()
  });
}

function assertAppCheckConfigured(request) {
  // Enable enforceAppCheck after the production app has App Check configured.
  // Rate limiting and server-side validation remain mandatory regardless.
  if (process.env.REQUIRE_APP_CHECK === 'true' && !request.app) {
    fail('failed-precondition', 'Требуется подтверждение App Check.');
  }
}

exports.submitStaffApplication = onCall({ region: REGION }, async (request) => {
  assertAppCheckConfigured(request);
  const fullName = requireString(request.data && request.data.fullName, 'fullName', 3, 120);
  const phone = requireString(request.data && request.data.phone, 'phone', 5, 32);
  const requestedDepartment = requireString(
    request.data && request.data.requestedDepartment,
    'requestedDepartment',
    1,
    100
  );
  const login = normalizeLogin(request.data && request.data.login);

  await applyRateLimit('application-ip', clientIp(request), 8, 60 * 60 * 1000);
  const appRef = db.collection(APPLICATIONS).doc();
  const reservationRef = db.collection(LOGIN_RESERVATIONS).doc(login);

  await db.runTransaction(async (tx) => {
    const reservation = await tx.get(reservationRef);
    if (reservation.exists && ['pending', 'pending_activation', 'active'].includes(reservation.data().status)) {
      fail('already-exists', 'Этот логин уже занят или ожидает рассмотрения.');
    }

    tx.set(appRef, {
      fullName,
      phone,
      requestedDepartment,
      loginNormalized: login,
      status: 'pending',
      createdAt: FieldValue.serverTimestamp(),
      reviewedAt: null,
      reviewedByUid: null
    });
    tx.set(reservationRef, {
      applicationId: appRef.id,
      status: 'pending',
      updatedAt: FieldValue.serverTimestamp()
    });
  });

  await audit('staff_application_submitted', null, { applicationId: appRef.id });
  return { applicationId: appRef.id, status: 'pending' };
});

exports.listStaffApplications = onCall({ region: REGION }, async (request) => {
  requireAdmin(request);
  const status = request.data && request.data.status ? String(request.data.status) : 'pending';
  if (!['pending', 'approved', 'active', 'rejected'].includes(status)) {
    fail('invalid-argument', 'Недопустимый фильтр статуса.');
  }
  const limit = Math.min(Math.max(Number(request.data && request.data.limit) || 50, 1), 100);
  const snapshot = await db.collection(APPLICATIONS)
    .where('status', '==', status)
    .orderBy('createdAt', 'desc')
    .limit(limit)
    .get();

  return {
    applications: snapshot.docs.map((doc) => {
      const data = doc.data();
      return {
        id: doc.id,
        fullName: data.fullName,
        phone: data.phone,
        requestedDepartment: data.requestedDepartment,
        departmentId: data.departmentId || null,
        login: data.loginNormalized,
        status: data.status,
        createdAt: data.createdAt ? data.createdAt.toMillis() : null,
        reviewedAt: data.reviewedAt ? data.reviewedAt.toMillis() : null,
        rejectionReason: data.rejectionReason || null
      };
    })
  };
});

exports.approveStaffApplication = onCall({ region: REGION }, async (request) => {
  const adminUid = requireAdmin(request);
  const applicationId = requireString(request.data && request.data.applicationId, 'applicationId', 1, 128);
  const departmentId = requireString(request.data && request.data.departmentId, 'departmentId', 1, 128);
  const appRef = db.collection(APPLICATIONS).doc(applicationId);
  const code = randomCode();
  const codeHash = hash(code);
  const uid = crypto.randomUUID();
  const expiresAt = Timestamp.fromMillis(Date.now() + ACTIVATION_TTL_MS);

  await db.runTransaction(async (tx) => {
    const appSnap = await tx.get(appRef);
    if (!appSnap.exists || appSnap.data().status !== 'pending') {
      fail('failed-precondition', 'Заявка не найдена или уже обработана.');
    }
    const app = appSnap.data();
    const login = app.loginNormalized;
    const reservationRef = db.collection(LOGIN_RESERVATIONS).doc(login);
    const loginRef = db.collection(LOGIN_INDEX).doc(login);
    // The current CRM stores departments in crm_data/main, not in a
    // top-level departments collection. Validate against that authoritative
    // document until the data migration creates normalized department docs.
    const [reservationSnap, loginSnap, crmSnap] = await Promise.all([
      tx.get(reservationRef),
      tx.get(loginRef),
      tx.get(db.collection('crm_data').doc('main'))
    ]);
    if (!reservationSnap.exists || reservationSnap.data().applicationId !== applicationId) {
      fail('failed-precondition', 'Резервирование логина не найдено.');
    }
    if (loginSnap.exists) fail('already-exists', 'Логин уже используется.');
    const departments = crmSnap.exists && Array.isArray(crmSnap.data().departments) ? crmSnap.data().departments : [];
    if (!departments.some((department) => department && department.id === departmentId)) {
      fail('not-found', 'Выбранный отдел не найден в CRM.');
    }

    tx.create(loginRef, {
      applicationId,
      uid,
      status: 'pending_activation',
      activationCodeHash: codeHash,
      activationExpiresAt: expiresAt,
      activationAttempts: 0
    });
    tx.update(reservationRef, { status: 'pending_activation', updatedAt: FieldValue.serverTimestamp() });
    tx.update(appRef, {
      status: 'approved',
      departmentId,
      approvedAt: FieldValue.serverTimestamp(),
      reviewedAt: FieldValue.serverTimestamp(),
      reviewedByUid: adminUid,
      activationExpiresAt: expiresAt
    });
  });

  await audit('staff_application_approved', adminUid, { applicationId, departmentId });
  return {
    activationCode: code,
    expiresAt: expiresAt.toMillis(),
    message: 'Покажите код сотруднику один раз через согласованный защищённый канал.'
  };
});

exports.rejectStaffApplication = onCall({ region: REGION }, async (request) => {
  const adminUid = requireAdmin(request);
  const applicationId = requireString(request.data && request.data.applicationId, 'applicationId', 1, 128);
  const reason = request.data && request.data.reason
    ? requireString(request.data.reason, 'reason', 1, 500)
    : null;
  const appRef = db.collection(APPLICATIONS).doc(applicationId);

  await db.runTransaction(async (tx) => {
    const appSnap = await tx.get(appRef);
    if (!appSnap.exists || appSnap.data().status !== 'pending') {
      fail('failed-precondition', 'Заявка не найдена или уже обработана.');
    }
    const login = appSnap.data().loginNormalized;
    const reservationRef = db.collection(LOGIN_RESERVATIONS).doc(login);
    tx.update(appRef, {
      status: 'rejected',
      rejectionReason: reason,
      reviewedAt: FieldValue.serverTimestamp(),
      reviewedByUid: adminUid
    });
    tx.set(reservationRef, {
      applicationId,
      status: 'rejected',
      updatedAt: FieldValue.serverTimestamp()
    });
  });

  await audit('staff_application_rejected', adminUid, { applicationId });
  return { success: true };
});

exports.activateStaffAccount = onCall({ region: REGION }, async (request) => {
  assertAppCheckConfigured(request);
  const login = normalizeLogin(request.data && request.data.login);
  const code = requireString(request.data && request.data.activationCode, 'activationCode', 20, 128);
  const password = validatePassword(request.data && request.data.password);
  await applyRateLimit('activation-ip', `${login}:${clientIp(request)}`, ACTIVATION_MAX_ATTEMPTS, 60 * 60 * 1000);
  const loginRef = db.collection(LOGIN_INDEX).doc(login);
  const loginSnap = await loginRef.get();

  if (!loginSnap.exists) fail('permission-denied', 'Неверный логин или код активации.');
  const initial = loginSnap.data();
  if (!['pending_activation', 'activating'].includes(initial.status)
      || initial.activationExpiresAt.toMillis() < Date.now()
      || !crypto.timingSafeEqual(Buffer.from(hash(code)), Buffer.from(initial.activationCodeHash))) {
    fail('permission-denied', 'Неверный логин или код активации.');
  }

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(loginRef);
    if (!snap.exists) fail('permission-denied', 'Неверный логин или код активации.');
    const data = snap.data();
    if (!['pending_activation', 'activating'].includes(data.status)
        || data.activationExpiresAt.toMillis() < Date.now()
        || data.activationCodeHash !== hash(code)) {
      fail('permission-denied', 'Неверный логин или код активации.');
    }
    if ((data.activationAttempts || 0) >= ACTIVATION_MAX_ATTEMPTS) {
      fail('resource-exhausted', 'Превышено число попыток активации.');
    }
    tx.update(loginRef, {
      status: 'activating',
      activationAttempts: (data.activationAttempts || 0) + 1
    });
  });

  const auth = getAuth();
  let user;
  try {
    user = await auth.getUser(initial.uid);
  } catch (error) {
    if (error.code !== 'auth/user-not-found') throw error;
    user = await auth.createUser({ uid: initial.uid, disabled: false });
  }

  const appRef = db.collection(APPLICATIONS).doc(initial.applicationId);
  const appSnap = await appRef.get();
  if (!appSnap.exists) fail('failed-precondition', 'Заявка не найдена.');
  const app = appSnap.data();

  await auth.setCustomUserClaims(user.uid, {
    role: 'staff',
    departmentId: app.departmentId
  });

  const passwordHash = await argon2.hash(password, ARGON_OPTIONS);
  const batch = db.batch();
  batch.set(db.collection(PROFILES).doc(user.uid), {
    fullName: app.fullName,
    phone: app.phone,
    departmentId: app.departmentId,
    status: 'active',
    createdAt: FieldValue.serverTimestamp(),
    approvedAt: app.approvedAt || FieldValue.serverTimestamp(),
    approvedByUid: app.reviewedByUid
  });
  batch.update(loginRef, {
    status: 'active',
    role: 'staff',
    passwordHash,
    passwordHashVersion: 1,
    activatedAt: FieldValue.serverTimestamp(),
    activationCodeHash: FieldValue.delete(),
    activationExpiresAt: FieldValue.delete(),
    activationAttempts: FieldValue.delete()
  });
  batch.update(appRef, {
    status: 'active',
    activatedAt: FieldValue.serverTimestamp()
  });
  batch.set(db.collection(LOGIN_RESERVATIONS).doc(login), {
    applicationId: initial.applicationId,
    uid: user.uid,
    status: 'active',
    updatedAt: FieldValue.serverTimestamp()
  });
  await batch.commit();

  await audit('staff_account_activated', user.uid, { applicationId: initial.applicationId });
  const customToken = await auth.createCustomToken(user.uid, {
    role: 'staff',
    departmentId: app.departmentId
  });
  return { customToken };
});

exports.loginWithPassword = onCall({ region: REGION }, async (request) => {
  assertAppCheckConfigured(request);
  const login = normalizeLogin(request.data && request.data.login);
  const password = typeof (request.data && request.data.password) === 'string'
    ? request.data.password
    : '';
  if (password.length > 256) fail('invalid-argument', 'Неверный логин или пароль.');

  const ip = clientIp(request);
  await applyRateLimit('login-ip', `${login}:${ip}`, LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_MS);
  // A second, broader account-level ceiling slows distributed guessing without permanent lockout.
  await applyRateLimit('login-account', login, 50, LOGIN_WINDOW_MS);

  const loginRef = db.collection(LOGIN_INDEX).doc(login);
  const snap = await loginRef.get();
  const record = snap.exists ? snap.data() : null;
  const candidateHash = record && record.status === 'active' && record.passwordHash
    ? record.passwordHash
    : await DUMMY_HASH_PROMISE;
  let valid = false;
  try {
    valid = await argon2.verify(candidateHash, password);
  } catch (_) {
    valid = false;
  }

  if (!record || record.status !== 'active' || !valid) {
    await audit('login_failed', null, { loginHash: hash(login) });
    fail('unauthenticated', 'Неверный логин или пароль.');
  }

  const role = record.role;
  if (!['admin', 'staff'].includes(role)) {
    fail('permission-denied', 'Учётная запись отключена.');
  }

  let departmentId;
  if (role === 'staff') {
    const profile = await db.collection(PROFILES).doc(record.uid).get();
    if (!profile.exists || profile.data().status !== 'active') {
      fail('permission-denied', 'Учётная запись отключена.');
    }
    departmentId = profile.data().departmentId;
  }

  const claims = role === 'admin' ? { role: 'admin' } : { role: 'staff', departmentId };
  const customToken = await getAuth().createCustomToken(record.uid, claims);
  await audit('login_succeeded', record.uid, { role });
  return { customToken };
});
