const { initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore } = require('firebase-admin/firestore');
const { onCall, HttpsError } = require('firebase-functions/v2/https');
const { randomBytes } = require('node:crypto');

initializeApp();
const auth = getAuth();
const db = getFirestore();
const PERMISSIONS = ['live_manage', 'live_end', 'ledger', 'station_rates', 'inventory', 'members'];

async function requireMaster(request) {
  if (!request.auth || request.auth.token.master !== true) {
    throw new HttpsError('permission-denied', 'Master administrator access required.');
  }
  const profile = await db.doc(`users/${request.auth.uid}`).get();
  if (!profile.exists || profile.data().role !== 'master' || profile.data().isLocked ||
      profile.data().requiresPasswordChange || profile.data().roleVersion !== request.auth.token.roleVersion) {
    throw new HttpsError('permission-denied', 'Master administrator session is no longer active. Sign in again.');
  }
}

function normalizeUsername(value) {
  const username = String(value || '').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(username)) {
    throw new HttpsError('invalid-argument', 'Username must be 3–32 characters and use letters, numbers, dots, dashes, or underscores.');
  }
  return username;
}

function authEmail(username) { return `${normalizeUsername(username)}@accounts.wondergamezone.invalid`; }

async function claimsFor(user, roles) {
  const isMaster = user.role === 'master';
  const role = (roles || []).find(item => item.name === user.role);
  const perms = Object.fromEntries(PERMISSIONS.map(key => [key, isMaster || role?.perms?.[key] === true]));
  return { master: isMaster, role: user.role || 'manager', location_id: user.location_id || 'ALL', roleVersion: user.roleVersion || 1, perms };
}

async function refreshClaims(uid, user) {
  const roleDoc = await db.doc('system_config/roles').get();
  await auth.setCustomUserClaims(uid, await claimsFor(user, roleDoc.data()?.list || []));
}

exports.provisionUser = onCall(async request => {
  await requireMaster(request);
  const username = normalizeUsername(request.data?.username);
  const password = randomBytes(18).toString('base64url');
  const { role, location_id } = request.data || {};
  if (!role || !location_id) throw new HttpsError('invalid-argument', 'Role and location are required.');
  if (role === 'master') throw new HttpsError('invalid-argument', 'Create a standard role account; master access is assigned through account editing.');
  const [rolesSnap, locationsSnap] = await Promise.all([db.doc('system_config/roles').get(), db.doc('system_config/locations').get()]);
  if (!(rolesSnap.data()?.list || []).some(item => item.name === role)) throw new HttpsError('invalid-argument', 'Unknown role.');
  if (!(locationsSnap.data()?.list || []).some(item => item.id === location_id)) throw new HttpsError('invalid-argument', 'Unknown location.');
  const existing = await db.collection('users').where('username', '==', username).limit(1).get();
  if (!existing.empty) throw new HttpsError('already-exists', 'Username already exists.');
  const userRecord = await auth.createUser({ email: authEmail(username), password, displayName: username, disabled: false });
  const profile = { username, role, location_id, roleVersion: 1, requiresPasswordChange: true, isLocked: false, createdAt: new Date().toISOString() };
  try {
    await db.doc(`users/${userRecord.uid}`).set(profile);
    await refreshClaims(userRecord.uid, profile);
  } catch (error) {
    await auth.deleteUser(userRecord.uid);
    await db.doc(`users/${userRecord.uid}`).delete().catch(() => {});
    throw new HttpsError('internal', 'Could not finish provisioning the account.');
  }
  return { uid: userRecord.uid, temporaryPassword: password };
});

exports.updateUser = onCall(async request => {
  await requireMaster(request);
  const { uid } = request.data || {};
  const username = normalizeUsername(request.data?.username);
  const role = String(request.data?.role || '');
  const location_id = String(request.data?.location_id || '');
  if (!uid || !role || !location_id) throw new HttpsError('invalid-argument', 'User, role, and location are required.');
  if ((role === 'master') !== (location_id === 'ALL')) throw new HttpsError('invalid-argument', 'Master accounts must use ALL; staff accounts must use a specific location.');
  const profileRef = db.doc(`users/${uid}`);
  const snap = await profileRef.get();
  if (!snap.exists) throw new HttpsError('not-found', 'User not found.');
  if (uid === request.auth.uid && role !== 'master') throw new HttpsError('failed-precondition', 'The active master account cannot demote itself.');
  const [rolesSnap, locationsSnap] = await Promise.all([db.doc('system_config/roles').get(), db.doc('system_config/locations').get()]);
  if (role !== 'master' && !(rolesSnap.data()?.list || []).some(item => item.name === role)) throw new HttpsError('invalid-argument', 'Unknown role.');
  if (location_id !== 'ALL' && !(locationsSnap.data()?.list || []).some(item => item.id === location_id)) throw new HttpsError('invalid-argument', 'Unknown location.');
  const duplicate = await db.collection('users').where('username', '==', username).limit(2).get();
  if (duplicate.docs.some(doc => doc.id !== uid)) throw new HttpsError('already-exists', 'Username already exists.');
  await auth.updateUser(uid, { email: authEmail(username), displayName: username });
  const updated = { ...snap.data(), username, role, location_id, roleVersion: (snap.data().roleVersion || 1) + 1 };
  await profileRef.set(updated);
  await refreshClaims(uid, updated);
  return { ok: true };
});

exports.setUserLocked = onCall(async request => {
  await requireMaster(request);
  const { uid, locked } = request.data || {};
  if (!uid || typeof locked !== 'boolean') throw new HttpsError('invalid-argument', 'User and lock state are required.');
  if (uid === request.auth.uid) throw new HttpsError('failed-precondition', 'You cannot lock your own active administrator account.');
  const profileRef = db.doc(`users/${uid}`);
  const profileSnap = await profileRef.get();
  if (!profileSnap.exists) throw new HttpsError('not-found', 'User not found.');
  await auth.updateUser(uid, { disabled: locked });
  const updated = { ...profileSnap.data(), isLocked: locked, roleVersion: (profileSnap.data()?.roleVersion || 1) + 1 };
  await profileRef.set(updated);
  await refreshClaims(uid, updated);
  await auth.revokeRefreshTokens(uid);
  return { ok: true };
});

exports.resetUserPassword = onCall(async request => {
  await requireMaster(request);
  const { uid, password } = request.data || {};
  if (!uid || typeof password !== 'string' || password.length < 12) {
    throw new HttpsError('invalid-argument', 'Temporary passcode must be at least 12 characters.');
  }
  const profileRef = db.doc(`users/${uid}`);
  const profileSnap = await profileRef.get();
  if (!profileSnap.exists) throw new HttpsError('not-found', 'User not found.');
  const updated = { ...profileSnap.data(), requiresPasswordChange: true, isLocked: false, roleVersion: (profileSnap.data().roleVersion || 1) + 1 };
  await profileRef.set(updated);
  await auth.updateUser(uid, { password, disabled: false });
  await refreshClaims(uid, updated);
  await auth.revokeRefreshTokens(uid);
  return { ok: true };
});

exports.deleteUser = onCall(async request => {
  await requireMaster(request);
  const { uid } = request.data || {};
  if (!uid || uid === request.auth.uid) throw new HttpsError('failed-precondition', 'Cannot delete the active administrator.');
  await auth.deleteUser(uid);
  await db.doc(`users/${uid}`).delete();
  return { ok: true };
});

exports.updateRolePolicies = onCall(async request => {
  await requireMaster(request);
  const roles = request.data?.roles;
  if (!Array.isArray(roles) || roles.some(role => !role.name || !role.perms)) {
    throw new HttpsError('invalid-argument', 'A valid role list is required.');
  }
  const normalized = roles.map(role => ({
    name: String(role.name).slice(0, 40),
    perms: Object.fromEntries(PERMISSIONS.map(key => [key, role.perms[key] === true]))
  }));
  if (normalized.some(role => role.name.toLowerCase() === 'master') || new Set(normalized.map(role => role.name.toLowerCase())).size !== normalized.length) {
    throw new HttpsError('invalid-argument', 'Role names must be unique; master is reserved.');
  }
  await db.doc('system_config/roles').set({ list: normalized });
  const users = await db.collection('users').get();
  await Promise.all(users.docs.map(async doc => {
    const updated = { ...doc.data(), roleVersion: (doc.data().roleVersion || 1) + 1 };
    await doc.ref.set(updated);
    await refreshClaims(doc.id, updated);
    if (doc.id !== request.auth.uid) await auth.revokeRefreshTokens(doc.id);
  }));
  return { ok: true };
});

exports.wipeSystem = onCall({ timeoutSeconds: 540, memory: '1GiB' }, async request => {
  await requireMaster(request);
  if (request.data?.confirmation !== 'PURGE ALL DATA') throw new HttpsError('failed-precondition', 'Confirmation phrase does not match.');
  const authTime = request.auth.token.auth_time || 0;
  if (Date.now() / 1000 - authTime > 300) throw new HttpsError('failed-precondition', 'Sign in again before purging system data.');
  const users = await db.collection('users').get();
  const locations = await db.collection('locations').get();
  for (const location of locations.docs) {
    await db.recursiveDelete(location.ref);
  }
  for (const doc of users.docs) {
    if (doc.id === request.auth.uid) continue;
    await auth.deleteUser(doc.id).catch(() => {});
    await doc.ref.delete();
  }
  await db.doc('system_config/locations').set({ list: [{ id: 'loc_base_01', name: 'Base Location' }] });
  await db.doc('system_config/roles').set({ list: [{ name: 'manager', perms: Object.fromEntries(PERMISSIONS.map(key => [key, true])) }] });
  return { ok: true };
});

exports.completePasswordChange = onCall(async request => {
  if (!request.auth) throw new HttpsError('unauthenticated', 'Sign in to change your passcode.');
  const password = request.data?.password;
  if (typeof password !== 'string' || password.length < 12) {
    throw new HttpsError('invalid-argument', 'Passcode must be at least 12 characters.');
  }
  const profileRef = db.doc(`users/${request.auth.uid}`);
  const profileSnap = await profileRef.get();
  if (!profileSnap.exists || profileSnap.data().isLocked || profileSnap.data().requiresPasswordChange !== true) {
    throw new HttpsError('permission-denied', 'This account is not in a required passcode reset.');
  }
  const account = await auth.getUser(request.auth.uid);
  const validAfter = Date.parse(account.tokensValidAfterTime || 0) / 1000;
  if ((request.auth.token.auth_time || 0) < validAfter) throw new HttpsError('unauthenticated', 'Sign in again before changing this passcode.');
  await auth.updateUser(request.auth.uid, { password });
  await profileRef.update({ requiresPasswordChange: false });
  return { ok: true };
});
