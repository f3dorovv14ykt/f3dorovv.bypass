"""GitHub API handler for uploading files."""

from github import Github, Auth, GithubException
import time
import os
import concurrent.futures
from typing import Optional
from config.settings import GITHUB_TOKEN, REPO_NAME
from utils.logger import log, updated_files, _UPDATED_FILES_LOCK


class GitHubHandler:
    def __init__(self):
        if GITHUB_TOKEN:
            self.g = Github(auth=Auth.Token(GITHUB_TOKEN))
        else:
            self.g = Github()

        self.repo = self.g.get_repo(REPO_NAME)

        # Check GitHub API limits
        try:
            remaining, limit = self.g.rate_limiting
            if remaining < 100:
                log(f"Warning: {remaining}/{limit} GitHub API requests remaining")
            else:
                log(f"Available GitHub API requests: {remaining}/{limit}")
        except Exception as e:
            log(f"Could not check GitHub API limits: {e}")

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Uploads a local file to GitHub repository.
        
        Returns:
            True on success, False on failure
        """
        if not self._file_exists(local_path):
            log(f"File {local_path} not found.")
            return False

        with open(local_path, "r", encoding="utf-8") as file:
            content = file.read()

        max_retries = 5

        for attempt in range(1, max_retries + 1):
            try:
                # Try to get the existing file to check for changes
                try:
                    file_in_repo = self.repo.get_contents(remote_path)
                    current_sha = file_in_repo.sha
                except GithubException as e_get:
                    if getattr(e_get, "status", None) == 404:
                        # File doesn't exist, create it
                        basename = self._get_basename(remote_path)
                        self.repo.create_file(
                            path=remote_path,
                            message=f"First commit {basename}: {self._get_timestamp()}",
                            content=content,
                        )
                        log(f"File {remote_path} created.")
                        self._add_to_updated_files(remote_path)
                        return True
                    else:
                        msg = e_get.data.get("message", str(e_get))
                        log(f"Error getting {remote_path}: {msg}")
                        return False

                try:
                    remote_content = file_in_repo.decoded_content.decode("utf-8", errors="replace")
                    if remote_content == content:
                        log(f"No changes for {remote_path}.")
                        return True
                except Exception:
                    pass

                # Update the file
                basename = self._get_basename(remote_path)
                try:
                    self.repo.update_file(
                        path=remote_path,
                        message=f"Update {basename}: {self._get_timestamp()}",
                        content=content,
                        sha=current_sha,
                    )
                    log(f"File {remote_path} updated in repository.")
                    self._add_to_updated_files(remote_path)
                    return True
                except GithubException as e_upd:
                    if getattr(e_upd, "status", None) == 409:
                        if attempt < max_retries:
                            wait_time = 0.5 * (2 ** (attempt - 1))
                            log(f"SHA conflict for {remote_path}, attempt {attempt}/{max_retries}, waiting {wait_time} sec")
                            time.sleep(wait_time)
                            continue
                        else:
                            log(f"Could not update {remote_path} after {max_retries} attempts")
                            return False
                    else:
                        msg = e_upd.data.get("message", str(e_upd))
                        log(f"Error uploading {remote_path}: {msg}")
                        return False

            except Exception as e_general:
                short_msg = str(e_general)
                if len(short_msg) > 200:
                    short_msg = short_msg[:200] + "…"
                log(f"Unexpected error updating {remote_path}: {short_msg}")
                return False

        log(f"Could not update {remote_path} after {max_retries} attempts")
        return False


    def upload_multiple_files(self, file_pairs: list, dry_run: bool = False) -> int:
        """Uploads multiple config files to GitHub.
        
        Returns:
            Number of failed uploads (0 = success)
        """
        max_workers_upload = max(2, min(6, len(file_pairs)))
        failures = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_upload) as upload_pool:
            upload_futures = []

            for local_path, remote_path in file_pairs:
                if dry_run:
                    log(f"Dry-run: skipping upload of {remote_path} (local path {local_path})")
                else:
                    upload_futures.append(
                        upload_pool.submit(self.upload_file, local_path, remote_path)
                    )

            for uf in concurrent.futures.as_completed(upload_futures):
                try:
                    result = uf.result()
                    # upload_file returns None on success, but may fail silently
                    # Count as failure if result is explicitly False
                    if result is False:
                        failures += 1
                except Exception as e:
                    log(f"Upload future failed: {e}")
                    failures += 1
        
        if failures > 0:
            log(f"WARNING: {failures} upload(s) failed")
        
        return failures