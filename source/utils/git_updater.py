"""Git-based file updater for GitHub Actions."""

import os
import subprocess
import time
from typing import List, Tuple, Optional
from utils.logger import log


class GitUpdater:
    """Handles git commit and push operations for GitHub Actions."""
    
    def __init__(self, repo_dir: str = None, output_prefix: str = "githubmirror/"):
        if repo_dir is None:
            self.repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        else:
            self.repo_dir = repo_dir
        
        self.output_prefix = output_prefix.rstrip("/")
        log(f"GitUpdater initialized for: {self.repo_dir}")
    
    def _run_git(self, *args, check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess:
        """Run git command with timeout."""
        cmd = ["git"] + list(args)
        log(f"Running: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.repo_dir,
                capture_output=True,
                text=True,
                check=check,
                timeout=timeout
            )
            
            if result.stdout:
                log(f"Git output: {result.stdout.strip()}")
            if result.stderr:
                log(f"Git stderr: {result.stderr.strip()}")
            
            return result
        except subprocess.TimeoutExpired:
            log(f"Git command timed out: {' '.join(cmd)}")
            raise
        except subprocess.CalledProcessError as e:
            log(f"Git command failed: {e.stderr}")
            raise
    
    def configure_git(self):
        """Configure git user for commits."""
        log("Configuring git user...")
        self._run_git("config", "user.name", "GitHub Actions")
        self._run_git("config", "user.email", "actions@github.com")
        log("Git user configured")
    
    def pull(self, branch: Optional[str] = None):
        """Pull latest changes from remote with rebase."""
        if branch is None:
            result = self._run_git("rev-parse", "--abbrev-ref", "HEAD")
            branch = result.stdout.strip()
        
        log(f"Pulling from origin/{branch}...")
        try:
            # First stash any local changes (can happen with temp files)
            self._run_git("stash", "push", "-m", "Auto-stash before pull", check=False)
            
            # Now pull with rebase
            self._run_git("pull", "--rebase", "origin", branch)
            log("Pull successful")
            
            # Pop stash if it was created
            self._run_git("stash", "pop", check=False)
        except subprocess.CalledProcessError as e:
            if "cannot pull with rebase" in e.stderr.lower() or "unstaged changes" in e.stderr.lower():
                # Force reset to clean state
                log("Warning: Had unstaged changes, resetting to clean state...")
                self._run_git("reset", "--hard", "HEAD", check=False)
                self._run_git("clean", "-fd", check=False)
                # Try pull again
                self._run_git("pull", "--rebase", "origin", branch)
                log("Pull successful after reset")
            else:
                raise
    
    def stage_files(self, file_pairs: List[Tuple[str, str]]):
        """Stage all generated files for commit."""
        log(f"Staging generated files...")
        
        # Simply stage ALL changes in the output directory
        # This handles new files, modifications, and deletions automatically
        self._run_git("add", "-A", self.output_prefix, check=False)
        
        # Also stage any root-level changes
        self._run_git("add", "-A", ".", check=False)
        
        log(f"Staging complete")
    
    def has_changes(self) -> bool:
        """Check if there are staged changes."""
        try:
            result = self._run_git("diff", "--cached", "--quiet", check=False)
            return result.returncode != 0
        except Exception:
            return False
    
    def commit(self, message: str = "Update VPN configs") -> bool:
        """Commit staged changes."""
        if not self.has_changes():
            log("No changes to commit")
            return False
        
        log(f"Committing: {message}")
        self._run_git("commit", "-m", message)
        return True
    
    def push(self, branch: Optional[str] = None, force: bool = False):
        """Push commits to remote."""
        if branch is None:
            result = self._run_git("rev-parse", "--abbrev-ref", "HEAD")
            branch = result.stdout.strip()
        
        log(f"Pushing to origin/{branch}...")
        
        if force:
            self._run_git("push", "-f", "origin", branch)
        else:
            self._run_git("push", "origin", branch)
        
        log("Push successful")
    
    def commit_and_push_files(self, file_pairs: List[Tuple[str, str]], 
                               commit_message: str = "Update VPN configs",
                               max_retries: int = 3) -> bool:
        """Complete workflow with retry logic for push conflicts.
        
        Note: In GitHub Actions, repo is already up-to-date from checkout step,
        so we skip the pull to avoid conflicts with generated files.
        """
        log("Starting git commit and push workflow...")
        
        try:
            self.configure_git()
            
            # Skip pull in GitHub Actions - repo is already up-to-date from checkout
            
            self.stage_files(file_pairs)
            
            if not self.has_changes():
                log("No changes detected, skipping commit")
                return True
            
            # Retry loop for push conflicts
            for attempt in range(max_retries):
                if self.commit(commit_message):
                    try:
                        self.push()
                        log("Git workflow completed successfully")
                        return True
                    except subprocess.CalledProcessError as e:
                        if attempt < max_retries - 1:
                            wait_time = (attempt + 1) * 5
                            log(f"Push failed (attempt {attempt + 1}/{max_retries}), waiting {wait_time}s...")
                            time.sleep(wait_time)
                            # In GitHub Actions, just retry push (no pull needed)
                        else:
                            log(f"Push failed after {max_retries} attempts: {e.stderr}")
                            return False
                else:
                    log("Commit failed or no changes")
                    return False
            
            return False
            
        except Exception as e:
            log(f"Git workflow failed with error: {e}")
            return False
