# Firebase security migration

The site now uses Firebase Authentication, callable Cloud Functions for account administration, and Firestore rules for branch and permission checks. Legacy `users/*` documents contain plaintext passcodes, so perform this cutover deliberately.

## One-time cutover

1. Back up the Firestore database before changing production data.
2. Enable the Email/Password provider in Firebase Authentication, then install the Functions dependencies with `cd functions && npm install`.
3. Schedule a maintenance window. Deploying the restrictive rules disables the old unauthenticated client until the migration and new hosting deployment finish.
4. Configure Firebase CLI for project `console-c1bd3` and deploy the Functions: `firebase deploy --only functions`.
5. Authenticate the migration operator with Google Application Default Credentials, then run a dry run from the project root: `GCLOUD_PROJECT=console-c1bd3 node scripts/migrate-users-to-auth.js`.
6. Review the usernames and errors. Fix duplicate or unsupported usernames and reset any passcodes shorter than six characters in the legacy app before proceeding.
7. Deploy the restrictive rules to stop the legacy client from making writes: `firebase deploy --only firestore:rules`.
8. Run the migration with `GCLOUD_PROJECT=console-c1bd3 node scripts/migrate-users-to-auth.js --apply`. It creates Firebase Auth accounts using existing passcodes, writes UID-keyed profiles and permission claims, and removes legacy user documents that used different IDs. Passwords are not printed.
9. Deploy hosting: `firebase deploy --only hosting`.
10. Ask staff to sign in with their existing username and passcode. They must change any passcode that was already marked for reset. Admin-created accounts receive a generated temporary passcode that must be shared privately.

The migration is dry-run by default. Do not expose `functions/` or service-account credentials through Hosting. The Firebase web API key in `index.html` identifies the project; Firestore rules and Authentication enforce access. Deploying Functions requires a Firebase project plan that supports Cloud Functions.

## Operational notes

- Firebase Authentication throttles repeated sign-in attempts; the app no longer keeps counters or passcodes in Firestore. Normal passcode changes require reauthentication.
- A locked account is disabled in Authentication and denied by Firestore rules.
- Master account provisioning, edits, resets, locking, deletion, role policy updates, and system purge run in trusted Functions.
- Branch data access is restricted by signed-in location and role claims. Role policy changes refresh claims for all profiles.
- Updated role claims are checked against a profile version, so existing sessions lose old permissions immediately. Reload or sign in again if access is denied after a master changes a role policy.
- Keep a backup and test this cutover against a staging copy before production. This workspace cannot deploy to Firebase unless an authorized CLI session is configured.
