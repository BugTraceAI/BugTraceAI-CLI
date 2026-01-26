# Remote Sync Configuration

This project is mirrored from a VPS. Use this information to sync missing files or updates.

## Server Details
- **IP:** 54.39.99.155
- **User:** ubuntu
- **SSH Port:** 22
- **Remote Path:** /home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI/

## Sync Commands
To sync from remote to local (excluding heavy/temp files):
```bash
rsync -avz -e "ssh -p 22" --exclude 'venv' --exclude 'node_modules' --exclude '__pycache__' --exclude '.git' --exclude 'logs' --exclude 'reports' --exclude 'data' --exclude 'uploads' --exclude 'backups' ubuntu@54.39.99.155:/home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI/ /home/albert/Tools/BugTraceAI/BugTraceAI-CLI/
```

To sync a specific file:
```bash
scp ubuntu@54.39.99.155:/home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI/path/to/file ./path/to/file
```

## local Environment
- Virtual Env: `.venv/bin/activate` (Created with python 3.12)
- Browser: Playwright Chromium installed.
