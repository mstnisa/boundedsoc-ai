# 🚀 Start Here — Run This Project With Zero Coding Experience

This guide assumes you have **never used a terminal, never installed developer
tools, and don't know what "git" or "Docker" mean.** Follow the steps in
order, exactly as written, and you will end up with a working security
dashboard running on your own computer, open in your web browser.

If you get stuck, jump to [Troubleshooting](#troubleshooting) near the
bottom — the most common problems are covered there.

**Time needed:** about 20–30 minutes, mostly spent waiting for downloads.
**Skills needed:** none. Copy-paste is the hardest part.

---

## What you're about to run

This is **AI SOC Workbench** — a demo security dashboard that shows how an
AI assistant can help a security analyst investigate an incident, while a
human stays in control of every decision. Everything in the demo is
synthetic (fake, safe) data — no real computers, accounts, or networks are
touched.

---

## Step 1 — Install Docker Desktop

Docker is a free tool that packages this whole project (database, backend,
dashboard) so it runs the same way on any computer, without you installing
anything else by hand.

1. Go to **https://www.docker.com/products/docker-desktop/**
2. Click the download button for your computer (**Windows** or **Mac**).
3. Open the downloaded installer and click through it (default options are
   fine). Your computer may ask to restart — allow it if so.
4. After installing, open the **Docker Desktop** app (search for it like any
   other app). Wait until it shows a message like **"Docker Desktop is
   running"** with a green/whale icon. Leave it open in the background —
   it needs to keep running for the rest of these steps.

---

## Step 2 — Download this project

You do **not** need to know Git for this. Use the ZIP download:

1. On this project's GitHub page, click the green **`< > Code`** button
   (near the top of the file list).
2. Click **"Download ZIP"**.
3. Find the downloaded file (usually in your **Downloads** folder) — it will
   be named something like `ai-soc-workbench-main.zip`.
4. Extract it:
   - **Windows**: right-click the ZIP → **"Extract All..."** → Extract.
   - **Mac**: double-click the ZIP — it unzips automatically.
5. You'll now have a folder named something like `ai-soc-workbench-main`.
   **Remember where this folder is** — you'll need to open it in the next
   step.

---

## Step 3 — Open a terminal inside that folder

A "terminal" is just a window where you type commands instead of clicking.

**Windows:**
1. Open the extracted folder in File Explorer.
2. Click once in the address bar at the top (where the folder path is
   shown), type `cmd`, and press **Enter**. A black window opens — this is
   your terminal, already pointed at the right folder.

**Mac:**
1. Open the extracted folder in Finder.
2. Right-click (or two-finger click) inside the folder → **"New Terminal at
   Folder"**. (If you don't see this option, open the **Terminal** app from
   Applications → Utilities, type `cd ` with a trailing space, then drag the
   folder from Finder into the Terminal window, and press Enter.)

Either way, you should now have a terminal window open, sitting inside the
project folder.

---

## Step 4 — Create your settings file

This project needs one small settings file. A template is already included
— you just need to make your own copy of it (no editing required for this
demo run).

Type this into your terminal and press **Enter**:

**Windows:**
```
copy .env.example .env
```

**Mac:**
```
cp .env.example .env
```

This creates a file called `.env` with safe, ready-to-use demo settings —
no real passwords, no paid API keys needed for anything in this guide.

---

## Step 5 — Start the project (one command)

Still in the same terminal, type:

```
docker-compose up
```

and press **Enter**.

**What happens next:** a lot of text will scroll by. The first time you run
this, it can take **several minutes** — Docker is downloading and building
everything it needs. This is normal. Don't close the window.

You'll know it's ready when the scrolling slows down and you see lines
mentioning things like `Uvicorn running` and `ready in ... ms`.

**Leave this terminal window open** — closing it stops the project. You can
minimize it and keep using your computer normally.

---

## Step 6 — Open the dashboard

Open your web browser (Chrome, Edge, Safari — any browser) and go to:

**http://localhost:5173**

You should see the **AI SOC Workbench** dashboard: a sidebar on the left,
and a mostly-empty overview (0 incidents) on the right. That's expected —
you haven't loaded any sample data yet. That's the next step.

---

## Step 7 — Load a sample security incident (no coding needed)

We'll feed the system one realistic (but entirely fake) security incident,
using the project's built-in API page — point-and-click, no commands.

1. Open a **new browser tab** and go to: **http://localhost:8000/docs**
   (this is an interactive API page that comes built into the project).
2. Find the row that says **`POST /alerts`** and click on it to expand it.
3. Click the **"Try it out"** button on the right side.
4. Now open the sample data file so you can copy its contents:
   - In the project folder, go into the `data` → `synthetic` folder.
   - Open the file **`demo_incident_powershell.json`** with a plain text
     editor (**Windows**: right-click → Open with → Notepad. **Mac**:
     right-click → Open With → TextEdit).
   - Select all the text (Ctrl+A / Cmd+A) and copy it (Ctrl+C / Cmd+C).
5. Back on the `/docs` page, click inside the big text box under **"Request
   body"**, select everything already there, and paste (Ctrl+V / Cmd+V) to
   replace it with the copied content.
6. Click the blue **"Execute"** button.
7. Scroll down slightly — you should see a response starting with code
   **200**, meaning it worked.
8. Go back to your dashboard tab (**http://localhost:5173**) and refresh
   the page. You should now see **1 incident** appear.

---

## Step 8 — Explore the dashboard

- Click on the incident title to open it.
- Click the **"MITRE Suggestions"** tab, then click **"Generate MITRE
  Suggestions"** — the AI will propose some technique matches, each with
  its evidence shown underneath.
- Try **Approve** or **Reject** on a suggestion — notice nothing happens
  automatically without you clicking; that's the whole point of this
  project (a human approves every AI claim).
- Check the **Audit Trail** page in the sidebar — every action you just
  took (and every AI suggestion, even rejected ones) is logged there.

Everything here runs on your own computer with fake data. Nothing is sent
to the real internet or any paid AI service — the default demo mode uses a
built-in, deterministic mock "AI" so this is completely safe to explore.

---

## Step 8.5 — Try the extra AI modules (also point-and-click)

Five extra AI modules live inside the same dashboard. All of them follow the
same rule as everything else here: the AI only *suggests* — nothing happens
for real until you click a button to confirm it.

**A small "ML: routine" or "ML: escalated" badge** — you'll notice this next
to incidents on the Dashboard and Incident Queue. A small built-in model
looks at each new incident and guesses whether it looks routine (like a
repeated port scan) or worth a closer look. It never hides or removes
anything — it's just a hint about where to look first.

**Remediation tab** (open an incident → click the **Remediation** tab):
1. Click **Draft Remediation Suggestion** — the AI proposes an example code
   fix for the security issue (this is only shown if you've already approved
   a MITRE suggestion on the MITRE tab for this incident — do that first if
   the button says nothing was found).
2. Click **Approve** on the suggestion.
3. A new button appears: **Create Pull Request**. Click it. By default this
   is *simulated* (safe, no real GitHub repo is touched) — you'll see a
   fake pull-request link appear. A real integration can be turned on later
   by an admin, but never by the AI on its own.

**Credential Exposure tab** (same incident, next tab over):
1. Click **Scan for Exposed Credentials** — this looks for things that look
   like leaked passwords or API keys in the incident's data. The real
   secret value is never shown or stored, only a masked version like
   `api_…1b2050`.
2. If something is found, click **Approve**, then a **Revoke Now** button
   appears. Click it to (safely, simulated by default) revoke it. It cannot
   be revoked before you approve it — that's enforced by the system, not
   just hidden in the screen.

**Compliance tab** (same incident, next tab over):
1. Pick a framework from the dropdown (OWASP Top 10, PCI DSS, ISO 27001, or
   GDPR).
2. Click **Map Approved Findings**. This links your already-approved MITRE
   findings to real controls in that framework — useful evidence when
   preparing for an audit. It's clearly labeled as informational, not an
   official certification.
3. See the overall picture any time from the **Compliance** link in the left
   sidebar — it shows, per framework, how many controls have at least one
   piece of evidence behind them.

**AI Tool Policies** (left sidebar → **Integrations**, scroll down):
This is the allow-list that controls what the two modules above are allowed
to do. By default it only allows creating a pull request and revoking a
secret — nothing else. Below it, the **AI Action Log** shows every attempt,
whether it was allowed or blocked, so you can always see what the AI tried
to do outside the system.

---

## Step 9 — Stop the project when you're done

Go back to the terminal window from Step 5, and:

1. Press **Ctrl+C** to stop it.
2. Then type `docker-compose down` and press Enter to fully shut everything
   down and free up the ports.

## Step 10 — Start it again later

No need to repeat the download or Step 4. Just:

1. Open a terminal in the project folder again (Step 3).
2. Run `docker-compose up` again (Step 5).
3. Go to http://localhost:5173.

Your previously loaded incident will still be there — the data is saved
between runs.

---

## Troubleshooting

**"docker-compose: command not found" / "'docker' is not recognized"**
Docker Desktop isn't installed, or isn't running yet. Open the Docker
Desktop app and wait for it to say it's running, then try again.

**Terminal shows errors mentioning "port is already allocated"**
Something else on your computer is already using one of the ports this
project needs (5173, 8000, 5432, 6379, or 5678). Close other apps that
might use these (another database, another web server), or restart your
computer, then try `docker-compose up` again.

**The dashboard page won't load / "This site can't be reached"**
Give it more time — the very first startup can take a few minutes while
Docker downloads everything. Check the terminal window; if it's still
scrolling or hasn't shown an error, it's still starting up.

**Nothing shows up after Step 7**
Double check the response in the `/docs` page said **200**, not an error
code. If it errored, make sure you pasted the *entire* contents of
`demo_incident_powershell.json`, including the outer `{` and `}`. Also make
sure you refreshed the dashboard tab after loading the data.

**I closed the terminal window by accident**
That's fine — just reopen a terminal in the project folder (Step 3) and run
`docker-compose up` again (Step 5).

**Docker Desktop asks about WSL 2 (Windows) or virtualization**
Accept its default recommendation and follow its own on-screen setup
steps — this is Docker installing a small helper component it needs on
Windows, and only needs to be done once.

---

## Want to go deeper?

This guide is intentionally the "just make it work" version. For the full
technical picture — architecture, running without Docker, running the test
suite, configuration options, and more — see:

- `README.md` — project overview, architecture, what's built and why
- `docs/setup-guide.md` — the technical setup guide (Docker and non-Docker paths)
- `docs/demo-walkthrough.md` — the same demo scenario walked through step by
  step with real API responses
- `docs/screenshots/` — screenshots of every screen with descriptions
