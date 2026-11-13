# Backend implementation status

Branch: `feature/secure-client-portal`

## Implemented in this branch

- Firebase Functions v2 scaffold targeting Node.js 22.
- Callable endpoint `submitStaffApplication`: creates only a pending staff application; does not create an Auth user or grant access.
- Callable endpoint `listStaffApplications`: admin-only listing with status filter and bounded page size.
- Callable endpoints `approveStaffApplication` and `rejectStaffApplication`: admin-only manual review; approval issues a random one-time activation code, rejection records the decision.
- Callable endpoint `activateStaffAccount`: validates activation code, stores Argon2id password hash, creates Firebase Auth user and staff claims, activates the profile, and returns a Firebase custom token for the initial session.
- Callable endpoint `loginWithPassword`: checks login/password server-side, returns a Firebase custom token, supports staff and provisioned admin accounts, and uses generic credential errors.
- Server-side Firestore rate-limit records for application submission, activation and login.
- Admin-only initial provisioning script that prompts for a password without echoing it.
- Deny-by-default Firestore Rules draft for the proposed collections, including assignment-only staff ticket access and admin-wide access.
- GitHub Actions workflow for Node.js syntax checks.

## Not yet implemented / required before release

- Staff registration and activation forms in the browser.
- Admin queue UI in the existing CRM.
- Client account authentication and secure contract-based client onboarding.
- Password reset/revocation, staff disable/reactivation, activation-code reissue and login rename workflows.
- Full Firestore Rules unit tests using Firebase Emulator Suite and callable-function integration tests.
- End-to-end migration of the existing `crm_data/main` data and UI data-access layer.
- App Check enforcement and production rate-limit tuning/monitoring.
- Security review, dependency lockfile and vulnerability review.

## Critical deployment warning

Do **not** deploy the current Firestore Rules to the existing production CRM. They intentionally deny access to the legacy `crm_data/main` document and would break the current application. Do not deploy Cloud Functions to production yet. First run the emulator test suite, build the new UI, migrate test data, verify all role boundaries, and approve a production cutover/rollback plan.

The backend code is a development implementation, not a production security certification. Password authentication via a custom login index and Firebase Custom Tokens needs independent review before use with real accounts or personal data.
