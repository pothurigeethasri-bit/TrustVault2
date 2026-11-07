# Going live (Render) and sharing the link safely

The site is protected by a **security PIN**: anyone who opens your link sees only the PIN page.
Login and registration appear only after the correct PIN is entered.

## 1. Deploy
1. Push the project to GitHub (`.env` is git-ignored: never commit it).
2. Render > **New + > Blueprint** > pick the repo. `render.yaml` creates the web service and a PostgreSQL database.
3. When asked, fill in:
   - `SEED_PASSWORD`: strong password for the demo accounts (change or deactivate them later).
   - `ACCESS_PIN`: the security PIN, 6+ characters (e.g. 8 random digits). Required: the app refuses to start in production without it.
   - `SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` and `APP_BASE_URL`: the mail account that sends verification links and the site's public `https://` address (see *Set up e-mail* below). Required: the app refuses to start in production without them.
4. Wait for the deploy. The health check is `/healthz` (open even with the PIN gate on).
5. Open `https://<your-app>.onrender.com`. You should land on the **PIN page**, not the login page.

## 1b. Set up e-mail (verification links)
New users enter their email, receive a link, and choose their username and password only after opening it.
- **Gmail:** turn on 2-step verification, create an *App password*, then `SMTP_HOST=smtp.gmail.com`, `SMTP_PORT=587`, `SMTP_SECURITY=starttls`, `SMTP_USER=you@gmail.com`, `SMTP_PASSWORD=<16-char app password>`, `SMTP_FROM=TrustVault <you@gmail.com>`.
- **Any provider** (Brevo, SendGrid, Mailgun, ...) works the same way: use its SMTP host, port 587 (`starttls`) or 465 (`ssl`) and its SMTP login. `SMTP_FROM` must be an address the provider allows you to send from (ideally a verified sender/domain, otherwise mail lands in spam).
- `APP_BASE_URL` must be the public address with no trailing slash, e.g. `https://trustvault.onrender.com`. Links in e-mails are built from it, never from the browser's request.
- Test it: open `/register`, enter an address you own, open the mail, finish step 2, sign in. A wrong SMTP login shows "We could not send the email right now" and the details are in the Render logs (`trustvault.mail`).
- The free Render tier may block outbound SMTP on port 25; ports 587 and 465 are fine.

## 2. Share it
- Send the **link** and the **PIN** through *different* channels (e.g. link by e-mail, PIN by phone/SMS).
- A visitor enters the PIN, then reaches `/login` or `/register`. New accounts are always Viewers and must verify their email first. Someone who opens the e-mailed link in a browser that has not passed the PIN is asked for the PIN, then lands on the link.
- Check **Admin > Security** to watch PIN attempts (`PIN_ATTEMPT`), throttling (`THROTTLED`) and logins.

## 3. Change the PIN (do this if it leaks, or when a project ends)
Render > service > Environment > edit `ACCESS_PIN` > save (redeploys). Everyone who had passed the old PIN is asked again,
including signed-in users on their next request.

## 4. Passwords
- A user can change their own password at `/account/password`.
- "Forgot password?" on the login page flags the account; the admin sees **reset requested** on *Admin > Users* and clicks
  **Reset password** to get a one-time temporary password, which they pass on privately. The user must choose a new one at next sign-in.
- If *no admin* can sign in: from a shell with `DATABASE_URL` set, run `python reset_admin_password.py <username>`.

## 5. Before the demo/launch checklist
- [ ] SMTP works: register a test address end to end and check the mail is not in spam; `APP_BASE_URL` is your real `https://` address.
- [ ] `COOKIE_SECURE=1` and `TRUST_PROXY=1` (already in `render.yaml`): needed for HTTPS cookies and so IP throttling sees real client IPs.
- [ ] `STORAGE_BACKEND=db` on Render (disk is wiped each deploy).
- [ ] Demo account passwords changed; unused accounts deactivated.
- [ ] Admin > Audit log > **Run integrity check** shows "Chain intact".
- [ ] Optional: `harden_db.py` (see README) so the app's DB role can only SELECT/INSERT the audit log.

Free tier notes: the web service sleeps when idle (first request is slow) and the free database expires; use a paid plan for real use.
