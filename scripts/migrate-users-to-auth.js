#!/usr/bin/env node
// One-time migration. Dry run by default; pass --apply to write changes.
const { initializeApp, applicationDefault } = require('../functions/node_modules/firebase-admin/app');
const { getAuth } = require('../functions/node_modules/firebase-admin/auth');
const { getFirestore, FieldValue } = require('../functions/node_modules/firebase-admin/firestore');

const projectId = process.env.GCLOUD_PROJECT || process.env.FIREBASE_PROJECT_ID;
if (!projectId) throw new Error('Set GCLOUD_PROJECT or FIREBASE_PROJECT_ID to the Firebase project ID.');
initializeApp({ credential: applicationDefault(), projectId });
const auth = getAuth();
const db = getFirestore();
const apply = process.argv.includes('--apply');
const permissionNames = ['live_manage', 'live_end', 'ledger', 'station_rates', 'inventory', 'members'];
const emailFor = username => `${username.toLowerCase()}@accounts.wondergamezone.invalid`;

async function main() {
  const [usersSnap, rolesSnap, locationsSnap] = await Promise.all([
    db.collection('users').get(), db.doc('system_config/roles').get(), db.doc('system_config/locations').get()
  ]);
  const roles = rolesSnap.data()?.list || [{ name: 'manager', perms: Object.fromEntries(permissionNames.map(p => [p, true])) }];
  const locations = locationsSnap.data()?.list || [{ id: 'loc_base_01', name: 'Base Location' }];
  const seen = new Set();
  const plan = [];

  for (const doc of usersSnap.docs) {
    const user = doc.data();
    const username = String(user.username || '').trim();
    const password = user.password;
    const normalized = username.toLowerCase();
    if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(normalized)) throw new Error(`Unsupported username on legacy user document ${doc.id}; fix it before migration.`);
    if (seen.has(normalized)) throw new Error(`Duplicate username after case normalization: ${username}`);
    seen.add(normalized);
    if (typeof password !== 'string' || password.length < 6) throw new Error(`Legacy user ${username} has no Firebase-compatible passcode. Reset it before migration.`);
    const role = user.role || 'manager';
    const locationId = user.location_id || 'ALL';
    if (role !== 'master' && !roles.some(candidate => candidate.name === role)) throw new Error(`User ${username} references missing role ${role}.`);
    if (role === 'master' ? locationId !== 'ALL' : !locations.some(location => location.id === locationId)) {
      throw new Error(`User ${username} references an invalid location (${locationId}).`);
    }
    const email = emailFor(normalized);
    let existing = null;
    try { existing = await auth.getUserByEmail(email); } catch (error) { if (error.code !== 'auth/user-not-found') throw error; }
    plan.push({ oldId: doc.id, user: { ...user, username: normalized }, email, existingUid: existing?.uid || null });
  }

  console.log(`${apply ? 'Applying' : 'Dry run'}: migrate ${plan.length} users into Firebase Authentication for ${projectId}.`);
  console.log(`Existing role policies: ${roles.length}; locations: ${locations.length}.`);
  if (!apply) {
    for (const item of plan) console.log(`  ${item.user.username} -> ${item.existingUid || '(new Firebase Auth account)'}`);
    console.log('No data changed. Rerun with --apply to migrate.');
    return;
  }

  if (!rolesSnap.exists) await db.doc('system_config/roles').set({ list: roles });
  if (!locationsSnap.exists) await db.doc('system_config/locations').set({ list: locations });
  const oldIds = new Set(plan.map(item => item.oldId));
  for (const item of plan) {
    let userRecord;
    if (item.existingUid) {
      userRecord = await auth.updateUser(item.existingUid, { password: item.user.password, disabled: item.user.isLocked === true });
    } else {
      userRecord = await auth.createUser({
        email: item.email,
        password: item.user.password,
        displayName: item.user.username,
        disabled: item.user.isLocked === true
      });
    }
    const uid = userRecord.uid;
    const profile = {
      username: item.user.username,
      role: item.user.role || 'manager',
      location_id: item.user.location_id || 'ALL',
      isLocked: item.user.isLocked === true,
      requiresPasswordChange: item.user.requiresPasswordChange === true,
      roleVersion: 1,
      migratedAt: FieldValue.serverTimestamp()
    };
    const role = profile.role === 'master' ? null : roles.find(candidate => candidate.name === profile.role);
    const isMaster = profile.role === 'master';
    const perms = Object.fromEntries(permissionNames.map(key => [key, isMaster || role?.perms?.[key] === true]));
    await auth.setCustomUserClaims(uid, { master: isMaster, role: profile.role, location_id: profile.location_id, roleVersion: profile.roleVersion, perms });
    await db.doc(`users/${uid}`).set(profile);
    if (item.oldId !== uid && oldIds.has(item.oldId)) await db.doc(`users/${item.oldId}`).delete();
    console.log(`Migrated ${profile.username}.`);
  }
  console.log('Migration complete. Deploy the new frontend only after deploying the Firestore rules.');
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
