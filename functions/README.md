# Backend development (Firebase)

This backend is under development. It is **not deployed** by this repository change.

## Prerequisites

- Node.js 22
- Firebase CLI
- A dedicated non-production Firebase project for emulator/deployment testing
- A service account only for trusted administrative provisioning; keep its JSON outside this repository

## Local setup

1. Install dependencies:

   `cd functions && npm install`

2. Start local emulators:

   `cd .. && firebase emulators:start --only auth,functions,firestore`

3. Configure the Firebase Functions emulator to use the local Auth and Firestore emulators. Never point this test workflow at the live CRM project.

4. Run syntax checks:

   `cd functions && npm run lint`

## Initial administrator

Create a Firebase Authentication user in the dedicated test project using a trusted administrative procedure. Then provision its login from a secure terminal:

```sh
cd functions
GOOGLE_APPLICATION_CREDENTIALS=/secure/path/service-account.json \
  node scripts/provision-admin.js FIREBASE_AUTH_UID admin-login
```

The script prompts for the initial password without echoing it. Do not put service-account JSON, passwords, or activation codes in Git.

The older `set-admin-claims.js` script only sets a role claim; it does not create a login-index record. Use `provision-admin.js` when enabling password login.

## Deployment safety

- Do not deploy `firestore.rules` to the current live CRM before the app has migrated away from the legacy `crm_data/main` document. The rules intentionally deny legacy access.
- Do not deploy functions to production until the project ID, billing, region, App Check, secrets, rate-limit behavior, emulator tests, and backup/rollback plan have been reviewed.
- Set `REQUIRE_APP_CHECK=true` only after App Check is configured for the intended app and validated in the test project.
- The custom password backend requires a security review before production use.

## Isolated Auth emulator smoke test

This test uses a Firebase demo project ID and refuses to bootstrap unless both Auth and Firestore emulator environment variables are present. It does not contact or modify the configured production Firebase project.

1. From the repository root, install dependencies in `functions` and start the emulators:

   `firebase emulators:start --project demo-yarmarka-test --only auth,functions,firestore`

2. In a second terminal, from `functions`, bootstrap a disposable admin account:

   `GCLOUD_PROJECT=demo-yarmarka-test FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099 FIRESTORE_EMULATOR_HOST=127.0.0.1:8080 npm run emulator:admin -- admin.test`

   Enter a test password of at least 14 characters when prompted. Use only throwaway test credentials.

3. Serve the static app locally (repository root):

   `python -m http.server 8000`

4. Open `http://127.0.0.1:8000/?emulator=1`. The explicit query flag connects the browser SDKs to Auth, Firestore and Functions emulators. Sign in with the test login and password.

5. The expected first milestone is successful Firebase Authentication sign-in and loading the administrator's pending-registration queue. If the queue is empty, that is expected until a test staff application is submitted.

6. Do not remove `?emulator=1` while testing. Without that flag, the app connects to the Firebase project configured in `index.html`.

The current test scope is deliberately limited: legacy CRM data and staff workspaces have not yet been migrated. Staff activation/login and full ticket access must not be treated as production-ready until the protected data migration and end-to-end emulator tests are complete.
