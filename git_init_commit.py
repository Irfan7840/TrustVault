import os
from pathlib import Path
from dulwich.repo import Repo
import dulwich.porcelain as porcelain

repo_path = Path(r"c:\Users\moham\Downloads\TrustVault")

# 1. Initialize Git repository if not already done
git_dir = repo_path / ".git"
if not git_dir.exists():
    repo = Repo.init(str(repo_path))
    print(f"Initialized new Git repository at {repo_path}")
else:
    repo = Repo(str(repo_path))
    print(f"Opened existing Git repository at {repo_path}")

# 2. Stage files
try:
    # Use porcelain.add to stage files
    porcelain.add(repo, paths=None)  # None stages tracked and untracked not ignored
    print("Staged files successfully.")
except Exception as e:
    print(f"Warning during staging: {e}")

# 3. Create initial commit
try:
    commit_id = porcelain.commit(
        repo,
        message=b"Initial commit: TrustVault secure document sharing enterprise SaaS",
        committer=b"TrustVault Developer <developer@trustvault.local>",
        author=b"TrustVault Developer <developer@trustvault.local>",
    )
    print(f"Commit created: {commit_id.decode('ascii') if isinstance(commit_id, bytes) else commit_id}")
except Exception as e:
    print(f"Commit note: {e}")
