# Git Setup Guide — AI-IDPS
# Complete step-by-step commands for macOS / Linux / Windows

# ============================================================
# PRE-FLIGHT: files to delete manually before running git add
# ============================================================
# - src/old versions/          ← delete entire folder
# - src/__pycache__/           ← delete (gitignored, but clean it anyway)
# - dataset/normal_traffic.xlsx
# - dataset/window_traffic.xlsx
# - logs/security_log.xlsx
# - logs/security_log.csv      ← delete from working dir (gitignored)
# - model.pkl                  ← root-level duplicate; delete it
# ============================================================


# ─── Step 1: Navigate to project root ───────────────────────
cd ai-idps


# ─── Step 2: Install Git LFS (once per machine) ─────────────
# macOS (Homebrew):
brew install git-lfs

# Ubuntu/Debian:
sudo apt install git-lfs

# Windows (Git for Windows ships with LFS):
# Run Git Bash as admin, then:
git lfs install --system

# Enable LFS for this repo:
git lfs install


# ─── Step 3: Initialize the repository ──────────────────────
git init
git branch -M main


# ─── Step 4: Stage files ────────────────────────────────────
git add .

# Verify what will be committed (should NOT include __pycache__,
# *.xlsx, logs/, old versions/, model.pkl at root):
git status

# Verify LFS is tracking .pkl files:
git lfs status


# ─── Step 5: First commit ───────────────────────────────────
git commit -m "feat: initial release — AI-IDPS hybrid detection system

- Rule-based engine: port scan, SYN flood, traffic burst detection
- Isolation Forest ML anomaly detector
- Decision fusion: MEDIUM / HIGH / CRITICAL threat levels
- Automatic IP blocking with configurable expiry
- CSV security event logger
- Evaluation suite and matplotlib visualisations
- argparse CLI with --demo and --iface flags"


# ─── Step 6: Connect to GitHub ──────────────────────────────
# Create repo on GitHub: name = ai-idps (no README, no .gitignore)
# Then:
git remote add origin https://github.com/<your-username>/ai-idps.git

# Verify:
git remote -v


# ─── Step 7: Push ───────────────────────────────────────────
git push -u origin main


# ─── Common errors ──────────────────────────────────────────

# Error: remote origin already exists
git remote remove origin
git remote add origin https://github.com/<your-username>/ai-idps.git

# Error: failed to push (non-fast-forward / diverged history)
git pull origin main --rebase
git push origin main

# Error: large file rejected (if LFS wasn't set up before first add)
git rm --cached models/window_model.pkl
git commit -m "chore: untrack model binary (use Git LFS)"
git lfs track "*.pkl"
git add .gitattributes models/window_model.pkl
git commit -m "chore: track model binary with Git LFS"
git push origin main


# ─── Semantic commit examples ────────────────────────────────
# feat:     new feature
git commit -m "feat: add Flask dashboard for real-time alert monitoring"

# fix:      bug fix
git commit -m "fix: correct SYN flood threshold in rule_engine"

# refactor: code improvement, no behaviour change
git commit -m "refactor: extract feature vector builder into standalone function"

# docs:     documentation only
git commit -m "docs: add architecture diagram and usage examples to README"

# chore:    maintenance (deps, config, CI)
git commit -m "chore: pin scikit-learn to 1.4.2 in requirements.txt"

# data:     dataset or model update
git commit -m "data: retrain Isolation Forest with 2x extended normal traffic"

# test:     add or update tests
git commit -m "test: add unit tests for rule_engine detection logic"


# ─── GitHub repository settings ─────────────────────────────
# Repo name:    ai-idps
# Description:  Hybrid AI + rule-based Intrusion Detection & Prevention System
#               built with Python, Scapy, and Isolation Forest
# Topics:       cybersecurity intrusion-detection machine-learning
#               anomaly-detection python scapy isolation-forest
#               network-security ids-ips
# Visibility:   Public
# License:      MIT (already in repo)
