#!/usr/bin/env python3
"""
Ephemeral Repository Synchronization Script

Synchronizes commits from an ephemeral repository back to the original
source repository, replaying all non-baseline commits while preserving
commit messages, authors, and timestamps.

Usage:
    ./git-focus-sync.py [--source <dir>] [--destination <dir>] [--force]
    ./git-focus-sync.py --help

Examples:
    ./git-focus-sync.py --source ./ephemeral
    ./git-focus-sync.py --destination ~/monorepo_clone
    ./git-focus-sync.py --force --quiet --source ./ephemeral

For more information, see ephemeral-repo-create-and-sync-specifications.md
"""

import sys
import os
import argparse
import signal
import hashlib
import subprocess
import tomllib
from pathlib import Path
from datetime import datetime, timezone

# Manifest version for metadata compatibility
MANIFEST_VERSION = "1.0"

# Default metadata filename
DEFAULT_METADATA_FILENAME = "metadata"


def handle_sigint(signum, frame):
    """
    Handle Control-C (SIGINT) by cleanly exiting.

    Args:
        signum: Signal number
        frame: Current stack frame
    """
    sys.stderr.write("^C\n")
    sys.exit(1)


def print_usage():
    """
    Print brief usage information to stderr.
    """
    sys.stderr.write("Usage: git-focus-sync.py [--source <dir>] [--destination <dir>] [--force]\n")
    sys.stderr.write("       git-focus-sync.py --help\n")


def print_help():
    """
    Print detailed help information to stderr.
    """
    help_text = """
Ephemeral Repository Synchronization Script

Synchronizes commits from an ephemeral repository back to the original
source repository, replaying all non-baseline commits.

Optional Arguments:
  --source <dir>         Path to the ephemeral repository (default: current directory).
  --destination <dir>    Override the original repository path stored in the metadata.
                         Use this if the original repository has been moved or cloned.
  --metadata <path>      Custom metadata filename (default: metadata).
  --force               Skip confirmation prompt.
  --dry-run             Show what would be done without doing it.
  --quiet               Suppress warnings and non-error output.
  --help                Show this help message.

Behavior:
  - Verifies metadata integrity (checksum and baseline commit).
  - Checks for uncommitted changes in both repositories.
  - Verifies branch matches the source branch.
  - Creates temporary branch for sync operations.
  - Detects files outside the original subset definition.
  - Replays all commits from ephemeral repo to temporary branch.
  - Preserves commit messages, authors, and timestamps.
  - Merges temporary branch on success or offers cleanup on failure.

Exit Codes:
  0 - Success
  1 - Error or user abort

For full specifications, see ephemeral-repo-create-and-sync-specifications.md
"""
    sys.stderr.write(help_text)


def parse_arguments():
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments, or None if invalid
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--source', type=str, help='Path to the ephemeral repository to sync from')
    parser.add_argument('--destination', type=str, help='Override path to the original repository to sync to')
    parser.add_argument('--metadata', type=str, default=DEFAULT_METADATA_FILENAME,
                       help='Custom metadata filename')
    parser.add_argument('--force', action='store_true', help='Skip confirmation prompt')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done')
    parser.add_argument('--quiet', action='store_true', help='Suppress warnings and non-error output')
    parser.add_argument('--help', action='store_true', help='Show help message')

    try:
        args = parser.parse_args()
    except SystemExit:
        # argparse encountered an error
        print_usage()
        return None

    if args.help:
        print_help()
        sys.exit(0)

    return args


def validate_argument_types(args):
    """
    Validate that argument types and combinations are valid.

    Args:
        args: Parsed command-line arguments

    Returns:
        bool: True if valid, False otherwise
    """
    # All arguments are optional and have appropriate types from argparse
    # No additional validation needed for this script
    return True


def resolve_path(path):
    """
    Resolve a path relative to current directory to absolute path.

    Args:
        path: Path string (relative or absolute)

    Returns:
        Path: Absolute Path object
    """
    return Path(path).resolve()


def run_git_command(args, cwd, operation_description=None, check_returncode=True, input_data=None):
    """
    Execute a git command with consistent error handling.

    Args:
        args: List of command arguments (e.g., ['git', 'rev-parse', 'HEAD'])
        cwd: Working directory for the command
        operation_description: Human-readable description for error messages
        check_returncode: Whether to treat non-zero return code as error
        input_data: Optional input to pass to command via stdin

    Returns:
        subprocess.CompletedProcess: Result object with returncode, stdout, stderr
        None: If command failed and check_returncode is True
    """
    try:
        result = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            input=input_data,
            check=False  # We'll handle return code ourselves
        )

        if check_returncode and result.returncode != 0:
            if operation_description:
                sys.stderr.write(f"Error: {operation_description}\n")
            if result.stderr:
                sys.stderr.write(f"{result.stderr}\n")
            return None

        return result

    except Exception as e:
        if operation_description:
            sys.stderr.write(f"Error: {operation_description}: {e}\n")
        else:
            sys.stderr.write(f"Error executing git command: {e}\n")
        return None


class TemporaryBranch:
    """
    Context manager for temporary branch operations.

    Handles the complete lifecycle of a temporary branch:
    - Creation and switching to temporary branch
    - Automatic switch back to original branch on exit
    - Merging on success
    - Cleanup offers on failure

    Usage:
        with TemporaryBranch(repo_path, branch_name, quiet) as temp_branch:
            # Work on temporary branch
            replay_commits(...)
            temp_branch.mark_success()  # Signal successful completion
        # Automatically switches back, merges, and cleans up
    """

    def __init__(self, repo_path, original_branch, quiet=False):
        """
        Initialize temporary branch context manager.

        Args:
            repo_path: Path to repository
            original_branch: Name of original branch
            quiet: Whether to suppress output
        """
        self.repo_path = Path(repo_path)
        self.original_branch = original_branch
        self.quiet = quiet
        self.temp_branch_name = None
        self.success = False
        self.entered = False

    def __enter__(self):
        """
        Enter context: create and switch to temporary branch.

        Returns:
            self: Context manager instance
        """
        self.entered = True

        # Generate timestamp-based branch name
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        self.temp_branch_name = f"{self.original_branch}_temp_{timestamp}"

        # Create and switch to temporary branch
        result = run_git_command(
            ['git', 'checkout', '-b', self.temp_branch_name],
            cwd=self.repo_path,
            operation_description=f"Failed to create temporary branch: {self.temp_branch_name}"
        )

        if result is None:
            raise RuntimeError(f"Could not create temporary branch: {self.temp_branch_name}")

        if not self.quiet:
            print(f"✓ Created temporary branch: {self.temp_branch_name}")

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Exit context: switch back, merge on success, or offer cleanup on failure.

        Args:
            exc_type: Exception type if exception occurred
            exc_value: Exception value if exception occurred
            traceback: Traceback if exception occurred

        Returns:
            bool: False to propagate exceptions, True to suppress
        """
        if not self.entered:
            return False

        # Always switch back to original branch
        if not self.quiet:
            print()

        result = run_git_command(
            ['git', 'checkout', self.original_branch],
            cwd=self.repo_path,
            operation_description=f"Failed to switch back to branch {self.original_branch}"
        )

        if result is None:
            # Critical failure - couldn't switch back
            sys.stderr.write(f"Error: Failed to switch back to original branch {self.original_branch}\n")
            sys.stderr.write(f"You are still on temporary branch: {self.temp_branch_name}\n")
            sys.stderr.write(f"Please switch back manually with:\n")
            sys.stderr.write(f"  cd {self.repo_path}\n")
            sys.stderr.write(f"  git checkout {self.original_branch}\n")
            return False

        if not self.quiet:
            print(f"✓ Switched to branch: {self.original_branch}")

        # Handle based on success or failure
        if self.success and exc_type is None:
            # Success path: merge and delete
            self._handle_success()
        else:
            # Failure path: offer cleanup
            self._handle_failure()

        # Don't suppress exceptions
        return False

    def mark_success(self):
        """
        Mark the operation as successful.

        Should be called after commits are successfully replayed.
        """
        self.success = True

    def _handle_success(self):
        """
        Handle successful sync: merge temporary branch and delete it.
        """
        # Merge temporary branch
        result = run_git_command(
            ['git', 'merge', self.temp_branch_name],
            cwd=self.repo_path,
            operation_description=f"Failed to merge temporary branch: {self.temp_branch_name}"
        )

        if result is None:
            sys.stderr.write(f"Error: Failed to merge temporary branch\n")
            sys.stderr.write(f"You can merge manually with:\n")
            sys.stderr.write(f"  cd {self.repo_path}\n")
            sys.stderr.write(f"  git merge {self.temp_branch_name}\n")
            sys.stderr.write(f"  git branch -d {self.temp_branch_name}\n")
            return

        if not self.quiet:
            print(f"✓ Merged temporary branch: {self.temp_branch_name}")

        # Delete temporary branch
        result = run_git_command(
            ['git', 'branch', '-d', self.temp_branch_name],
            cwd=self.repo_path,
            check_returncode=False
        )

        if result and result.returncode == 0:
            if not self.quiet:
                print(f"✓ Deleted branch: {self.temp_branch_name}")
        else:
            sys.stderr.write(f"Warning: Sync succeeded but could not delete temporary branch: {self.temp_branch_name}\n")
            sys.stderr.write(f"You may want to delete it manually with:\n")
            sys.stderr.write(f"  cd {self.repo_path}\n")
            sys.stderr.write(f"  git branch -d {self.temp_branch_name}\n")

    def _handle_failure(self):
        """
        Handle failed sync: offer to delete temporary branch.
        """
        sys.stderr.write(f"\n{'='*60}\n")
        sys.stderr.write(f"SYNC FAILED - CLEANUP OPTIONS\n")
        sys.stderr.write(f"{'='*60}\n")
        sys.stderr.write(f"\nA temporary branch was created: {self.temp_branch_name}\n")
        sys.stderr.write(f"\nWould you like to delete the temporary branch? [Y/n]: ")
        sys.stderr.flush()

        choice = sys.stdin.readline().strip().lower()

        if choice in ['n', 'no']:
            print(f"\n✓ Temporary branch kept: {self.temp_branch_name}")
            print(f"  You can inspect it with:")
            print(f"    cd {self.repo_path}")
            print(f"    git checkout {self.temp_branch_name}")
            print(f"  To delete it later:")
            print(f"    cd {self.repo_path}")
            print(f"    git branch -D {self.temp_branch_name}")
        else:
            # Delete the temporary branch
            result = run_git_command(
                ['git', 'branch', '-D', self.temp_branch_name],
                cwd=self.repo_path,
                check_returncode=False
            )

            if result and result.returncode == 0:
                print(f"\n✓ Temporary branch deleted: {self.temp_branch_name}")
            else:
                sys.stderr.write(f"\nFailed to delete temporary branch.\n")
                sys.stderr.write(f"You can delete it manually with:\n")
                sys.stderr.write(f"  cd {self.repo_path}\n")
                sys.stderr.write(f"  git branch -D {self.temp_branch_name}\n")


def validate_repository(repo_path, repo_name):
    """
    Validate that a path is a valid git repository.

    Args:
        repo_path: Path to validate
        repo_name: Human-readable name for error messages

    Returns:
        bool: True if valid, False otherwise
    """
    if not repo_path.exists():
        sys.stderr.write(f"Error: {repo_name} does not exist: {repo_path}\n")
        return False

    if not repo_path.is_dir():
        sys.stderr.write(f"Error: {repo_name} is not a directory: {repo_path}\n")
        return False

    git_dir = repo_path / '.git'
    if not git_dir.exists():
        sys.stderr.write(f"Error: {repo_name} is not a git repository: {repo_path}\n")
        return False

    result = run_git_command(
        ['git', 'rev-parse', '--git-dir'],
        cwd=repo_path,
        operation_description=f"{repo_name} is not a valid git repository: {repo_path}"
    )

    return result is not None


def locate_metadata(ephemeral_path, metadata_filename):
    """
    Locate the metadata file in the ephemeral repository.

    Args:
        ephemeral_path: Path to ephemeral repository
        metadata_filename: Name of metadata file

    Returns:
        Path: Path to metadata file, or None if not found
    """
    metadata_path = ephemeral_path / metadata_filename

    if not metadata_path.exists():
        sys.stderr.write(f"Error: Metadata file not found: {metadata_path}\n")
        sys.stderr.write(f"Expected location: {ephemeral_path / metadata_filename}\n")
        return None

    return metadata_path


def parse_metadata(metadata_path, quiet=False):
    """
    Parse the TOML metadata file.

    Args:
        metadata_path: Path to metadata file
        quiet: Whether to suppress output

    Returns:
        dict: Parsed metadata, or None on error
    """
    try:
        with open(metadata_path, 'rb') as f:
            metadata = tomllib.load(f)

        # Validate required fields
        required_fields = ['session_id', 'manifest_version', 'baseline_commit',
                          'original_repo_path', 'subset']

        for field in required_fields:
            if field not in metadata:
                sys.stderr.write(f"Error: Missing required field in metadata: {field}\n")
                return None

        if 'paths' not in metadata['subset']:
            sys.stderr.write(f"Error: Missing 'paths' in subset section of metadata\n")
            return None

        if not quiet:
            print(f"✓ Parsed metadata file")
            print(f"  Session ID: {metadata['session_id']}")
            print(f"  Manifest version: {metadata['manifest_version']}")
            print(f"  Baseline commit: {metadata['baseline_commit']}")
            print(f"  Original repository (from metadata): {metadata['original_repo_path']}")
            if 'source_branch' in metadata:
                print(f"  Source branch: {metadata['source_branch']}")
            print(f"  Subset paths: {len(metadata['subset']['paths'])}")

        return metadata

    except Exception as e:
        sys.stderr.write(f"Error: Failed to parse metadata file: {e}\n")
        return None


def validate_manifest_version(metadata_version, quiet=False):
    """
    Validate that the metadata manifest version matches the script version.

    Args:
        metadata_version: Version string from metadata
        quiet: Whether to suppress output

    Returns:
        bool: True if version matches or user confirms to proceed, False otherwise
    """
    if metadata_version == MANIFEST_VERSION:
        if not quiet:
            print(f"✓ Manifest version matches: {MANIFEST_VERSION}")
        return True

    sys.stderr.write(f"Warning: Manifest version mismatch!\n")
    sys.stderr.write(f"  Script version:   {MANIFEST_VERSION}\n")
    sys.stderr.write(f"  Metadata version: {metadata_version}\n")
    sys.stderr.write(f"\nThis may indicate incompatibility. Proceed anyway? [y/N]: ")
    sys.stderr.flush()

    choice = sys.stdin.readline().strip().lower()

    if choice in ['y', 'yes']:
        return True
    else:
        sys.stderr.write("Aborted by user.\n")
        return False


def verify_checksum(metadata_path, quiet=False):
    """
    Verify that the metadata file checksum matches the checksum file.

    Args:
        metadata_path: Path to metadata file
        quiet: Whether to suppress output

    Returns:
        bool: True if checksum matches or user confirms to proceed, False otherwise
    """
    checksum_path = metadata_path.parent / f"{metadata_path.name}.sha256"

    if not checksum_path.exists():
        sys.stderr.write(f"Error: Checksum file not found: {checksum_path}\n")
        return False

    try:
        # Read metadata file
        with open(metadata_path, 'rb') as f:
            metadata_content = f.read()

        # Calculate SHA256
        calculated_hash = hashlib.sha256(metadata_content).hexdigest()

        # Read checksum file
        with open(checksum_path, 'r') as f:
            stored_hash = f.read().strip()

        if calculated_hash == stored_hash:
            if not quiet:
                print(f"✓ Checksum verification passed")
            return True
        else:
            sys.stderr.write(f"Warning: Checksum mismatch!\n")
            sys.stderr.write(f"  Calculated: {calculated_hash}\n")
            sys.stderr.write(f"  Stored:     {stored_hash}\n")
            sys.stderr.write(f"\nMetadata file may have been modified. Proceed anyway? [y/N]: ")
            sys.stderr.flush()

            choice = sys.stdin.readline().strip().lower()

            if choice in ['y', 'yes']:
                return True
            else:
                sys.stderr.write("Aborted by user.\n")
                return False

    except Exception as e:
        sys.stderr.write(f"Error: Failed to verify checksum: {e}\n")
        return False


def validate_original_repo(original_repo_path, quiet=False):
    """
    Validate that the original repository path is a git repository.

    Args:
        original_repo_path: Path to validate
        quiet: Whether to suppress output

    Returns:
        bool: True if valid git repository, False otherwise
    """
    repo_path = Path(original_repo_path)
    git_dir = repo_path / '.git'

    if not repo_path.exists():
        sys.stderr.write(f"Error: Original repository path does not exist: {original_repo_path}\n")
        return False

    if not repo_path.is_dir():
        sys.stderr.write(f"Error: Original repository path is not a directory: {original_repo_path}\n")
        return False

    if not git_dir.exists():
        sys.stderr.write(f"Error: Original repository path is not a git repository: {original_repo_path}\n")
        return False

    result = run_git_command(
        ['git', 'rev-parse', '--git-dir'],
        cwd=repo_path,
        operation_description=f"Original repository path is not a valid git repository: {original_repo_path}"
    )

    if result is not None and not quiet:
        print(f"✓ Validated original repository: {original_repo_path}")

    return result is not None


def get_current_commit(repo_path):
    """
    Get the current HEAD commit hash of a repository.

    Args:
        repo_path: Repository path

    Returns:
        str: Commit hash, or None on error
    """
    result = run_git_command(
        ['git', 'rev-parse', 'HEAD'],
        cwd=repo_path,
        operation_description="Failed to get current commit"
    )

    return result.stdout.strip() if result else None


def get_current_branch(repo_path):
    """
    Get the current branch name of a repository.

    Args:
        repo_path: Repository path

    Returns:
        str: Branch name, or None if detached HEAD or error
    """
    result = run_git_command(
        ['git', 'symbolic-ref', '--short', 'HEAD'],
        cwd=repo_path,
        check_returncode=False
    )

    if result and result.returncode == 0:
        branch = result.stdout.strip()
        return branch if branch else None

    return None


def verify_branch_match(original_repo_path, expected_branch, quiet=False):
    """
    Verify that the original repository is on the expected branch.

    Args:
        original_repo_path: Path to original repository
        expected_branch: Expected branch name from metadata
        quiet: Whether to suppress output

    Returns:
        bool: True if branch matches or user confirms to proceed, False otherwise
    """
    current_branch = get_current_branch(Path(original_repo_path))

    if current_branch is None:
        sys.stderr.write(f"Error: Original repository is in detached HEAD state\n")
        sys.stderr.write(f"The ephemeral repository was created from branch '{expected_branch}'.\n")
        sys.stderr.write(f"\nPlease checkout the correct branch first:\n")
        sys.stderr.write(f"  cd {original_repo_path}\n")
        sys.stderr.write(f"  git checkout {expected_branch}\n")
        return False

    if current_branch != expected_branch:
        sys.stderr.write(f"Warning: Branch mismatch!\n")
        sys.stderr.write(f"  Expected branch: {expected_branch}\n")
        sys.stderr.write(f"  Current branch:  {current_branch}\n")
        sys.stderr.write(f"\nThe ephemeral repository was created from '{expected_branch}',\n")
        sys.stderr.write(f"but the original repository is now on '{current_branch}'.\n")
        sys.stderr.write(f"\nCommits will be replayed on '{current_branch}' instead.\n")
        sys.stderr.write(f"This may not be what you want.\n")
        sys.stderr.write(f"\nTo sync to the original branch, run:\n")
        sys.stderr.write(f"  cd {original_repo_path}\n")
        sys.stderr.write(f"  git checkout {expected_branch}\n")
        sys.stderr.write(f"\nContinue syncing to '{current_branch}' anyway? [y/N]: ")
        sys.stderr.flush()

        choice = sys.stdin.readline().strip().lower()

        if choice in ['y', 'yes']:
            return True
        else:
            sys.stderr.write("Aborted by user.\n")
            return False

    if not quiet:
        print(f"✓ Branch matches: {expected_branch}")

    return True


def verify_baseline_commit(original_repo_path, baseline_commit, quiet=False):
    """
    Verify that the original repository HEAD matches the baseline commit.

    Args:
        original_repo_path: Path to original repository
        baseline_commit: Expected baseline commit hash
        quiet: Whether to suppress output

    Returns:
        bool: True if matches or user confirms to proceed, False otherwise
    """
    current_commit = get_current_commit(Path(original_repo_path))
    if current_commit is None:
        return False

    if current_commit == baseline_commit:
        if not quiet:
            print(f"✓ Baseline commit matches current HEAD")
        return True

    sys.stderr.write(f"Warning: Original repository branch has diverged!\n")
    sys.stderr.write(f"  Expected (baseline): {baseline_commit}\n")
    sys.stderr.write(f"  Current HEAD:        {current_commit}\n")
    sys.stderr.write(f"\nThe original branch has advanced since the ephemeral repository was created.\n")
    sys.stderr.write(f"Commits will be replayed on top of the current HEAD.\n")
    sys.stderr.write(f"This may result in merge conflicts.\n")
    sys.stderr.write(f"\nContinue anyway? [y/N]: ")
    sys.stderr.flush()

    choice = sys.stdin.readline().strip().lower()

    if choice in ['y', 'yes']:
        return True
    else:
        sys.stderr.write("Aborted by user.\n")
        return False


def get_initial_commit(repo_path):
    """
    Get the hash of the initial (first) commit in a repository.

    Args:
        repo_path: Repository path

    Returns:
        str: Commit hash, or None on error
    """
    result = run_git_command(
        ['git', 'rev-list', '--max-parents=0', 'HEAD'],
        cwd=repo_path,
        operation_description="Failed to get initial commit"
    )

    return result.stdout.strip() if result else None


def get_commit_files(repo_path, commit_hash):
    """
    Get the list of files in a specific commit.

    Args:
        repo_path: Repository path
        commit_hash: Commit hash to inspect

    Returns:
        set: Set of file paths in the commit, or None on error
    """
    result = run_git_command(
        ['git', 'ls-tree', '-r', '--name-only', commit_hash],
        cwd=repo_path,
        operation_description="Failed to get commit files"
    )

    if result:
        files = set(result.stdout.strip().split('\n')) if result.stdout.strip() else set()
        return files

    return None


def verify_initial_commit_content(ephemeral_path, original_repo_path, baseline_commit,
                                   subset_paths, quiet=False):
    """
    Verify that the ephemeral repository's initial commit matches the baseline.

    Args:
        ephemeral_path: Path to ephemeral repository
        original_repo_path: Path to original repository
        baseline_commit: Baseline commit hash
        subset_paths: List of paths that should be in the subset
        quiet: Whether to suppress output

    Returns:
        bool: True if matches or user confirms to proceed, False otherwise
    """
    # Get initial commit of ephemeral repo
    initial_commit = get_initial_commit(ephemeral_path)
    if initial_commit is None:
        return False

    # Get files in ephemeral repo's initial commit
    ephemeral_files = get_commit_files(ephemeral_path, initial_commit)
    if ephemeral_files is None:
        return False

    # Expand subset paths to expected files
    expected_files = set()
    original_path = Path(original_repo_path)

    for path_str in subset_paths:
        path = original_path / path_str
        if path.is_file():
            expected_files.add(path_str)
        elif path.is_dir():
            # Get all files in the directory from the baseline commit
            result = run_git_command(
                ['git', 'ls-tree', '-r', '--name-only', baseline_commit, path_str],
                cwd=original_path,
                check_returncode=False
            )

            if result and result.returncode == 0:
                dir_files = result.stdout.strip().split('\n') if result.stdout.strip() else []
                expected_files.update(dir_files)

    # Compare file sets
    if ephemeral_files == expected_files:
        if not quiet:
            print(f"✓ Initial commit content matches baseline")
        return True

    missing = expected_files - ephemeral_files
    extra = ephemeral_files - expected_files

    sys.stderr.write(f"Warning: Initial commit content does not match baseline!\n")
    if missing:
        sys.stderr.write(f"  Missing files: {len(missing)}\n")
        for f in sorted(list(missing)[:5]):
            sys.stderr.write(f"    - {f}\n")
        if len(missing) > 5:
            sys.stderr.write(f"    ... and {len(missing) - 5} more\n")

    if extra:
        sys.stderr.write(f"  Extra files: {len(extra)}\n")
        for f in sorted(list(extra)[:5]):
            sys.stderr.write(f"    - {f}\n")
        if len(extra) > 5:
            sys.stderr.write(f"    ... and {len(extra) - 5} more\n")

    sys.stderr.write(f"\nProceed anyway? [y/N]: ")
    sys.stderr.flush()

    choice = sys.stdin.readline().strip().lower()

    if choice in ['y', 'yes']:
        return True
    else:
        sys.stderr.write("Aborted by user.\n")
        return False


def detect_uncommitted_changes(repo_path, repo_name, quiet=False):
    """
    Check if a repository has uncommitted changes.

    Args:
        repo_path: Repository path
        repo_name: Human-readable name for error messages
        quiet: Whether to suppress output

    Returns:
        bool: True if no uncommitted changes, False otherwise
    """
    # Check for modified/deleted files
    result = run_git_command(
        ['git', 'diff', '--name-only'],
        cwd=repo_path,
        operation_description=f"Failed to check for uncommitted changes in {repo_name}"
    )

    if result is None:
        return False

    if result.stdout.strip():
        sys.stderr.write(f"Error: {repo_name} has uncommitted changes (modified files):\n")
        sys.stderr.write(result.stdout)
        sys.stderr.write(f"\nPlease commit or stash changes before syncing.\n")
        return False

    # Check for staged changes
    result = run_git_command(
        ['git', 'diff', '--cached', '--name-only'],
        cwd=repo_path,
        operation_description=f"Failed to check for staged changes in {repo_name}"
    )

    if result is None:
        return False

    if result.stdout.strip():
        sys.stderr.write(f"Error: {repo_name} has uncommitted changes (staged files):\n")
        sys.stderr.write(result.stdout)
        sys.stderr.write(f"\nPlease commit or unstage changes before syncing.\n")
        return False

    # Don't check for untracked files - just ignore them in both repositories

    if not quiet:
        print(f"✓ No uncommitted changes in {repo_name}")

    return True


def get_all_files_in_repo(repo_path):
    """
    Get all tracked files in a repository.

    Args:
        repo_path: Repository path

    Returns:
        set: Set of file paths, or None on error
    """
    result = run_git_command(
        ['git', 'ls-files'],
        cwd=repo_path,
        operation_description="Failed to get repository files"
    )

    if result:
        files = set(result.stdout.strip().split('\n')) if result.stdout.strip() else set()
        return files

    return None


def expand_subset_paths_to_files(subset_paths, original_repo_path):
    """
    Expand subset path specifications to actual file paths.

    Args:
        subset_paths: List of path specifications
        original_repo_path: Path to original repository

    Returns:
        set: Set of file paths, or None on error
    """
    files = set()
    original_path = Path(original_repo_path)

    for path_str in subset_paths:
        path = original_path / path_str

        if path.is_file():
            files.add(path_str)
        elif path.is_dir():
            # Get all tracked files in directory
            result = run_git_command(
                ['git', 'ls-files', path_str],
                cwd=original_path,
                check_returncode=False
            )

            if result and result.returncode == 0:
                dir_files = result.stdout.strip().split('\n') if result.stdout.strip() else []
                files.update(dir_files)

    return files


def detect_outofscope_files(ephemeral_path, subset_paths, original_repo_path, quiet=False):
    """
    Detect files in ephemeral repository that are outside the original subset.

    Args:
        ephemeral_path: Path to ephemeral repository
        subset_paths: List of original subset paths
        original_repo_path: Path to original repository
        quiet: Whether to suppress output

    Returns:
        bool: True if no out-of-scope files or user confirms to proceed, False otherwise
    """
    # Get all files currently in ephemeral repo
    ephemeral_files = get_all_files_in_repo(ephemeral_path)
    if ephemeral_files is None:
        return False

    # Remove metadata files from consideration
    ephemeral_files.discard('metadata')
    ephemeral_files.discard('metadata.sha256')

    # Expand subset paths to expected files
    expected_files = expand_subset_paths_to_files(subset_paths, original_repo_path)
    if expected_files is None:
        return False

    # Find out-of-scope files
    out_of_scope = ephemeral_files - expected_files

    if not out_of_scope:
        if not quiet:
            print(f"✓ No out-of-scope files detected")
        return True

    sys.stderr.write(f"Warning: Files detected outside original subset definition!\n")
    sys.stderr.write(f"  Out-of-scope files: {len(out_of_scope)}\n")
    for f in sorted(list(out_of_scope)[:10]):
        sys.stderr.write(f"    - {f}\n")
    if len(out_of_scope) > 10:
        sys.stderr.write(f"    ... and {len(out_of_scope) - 10} more\n")

    sys.stderr.write(f"\nThese files will be included in the replayed commits.\n")
    sys.stderr.write(f"Proceed anyway? [y/N]: ")
    sys.stderr.flush()

    choice = sys.stdin.readline().strip().lower()

    if choice in ['y', 'yes']:
        return True
    else:
        sys.stderr.write("Aborted by user.\n")
        return False


def get_commits_to_replay(ephemeral_path):
    """
    Get list of commits to replay (all except the initial commit).

    Args:
        ephemeral_path: Path to ephemeral repository

    Returns:
        list: List of commit hashes (oldest to newest), or None on error
    """
    # Get initial commit
    initial_commit = get_initial_commit(ephemeral_path)
    if initial_commit is None:
        return None

    # Get all commits after initial commit
    result = run_git_command(
        ['git', 'rev-list', '--reverse', f'{initial_commit}..HEAD'],
        cwd=ephemeral_path,
        operation_description="Failed to get commits to replay"
    )

    if result:
        commits = result.stdout.strip().split('\n') if result.stdout.strip() else []
        return commits

    return None


def get_commit_info(repo_path, commit_hash):
    """
    Get information about a commit.

    Args:
        repo_path: Repository path
        commit_hash: Commit hash

    Returns:
        dict: Commit info with keys: message, author, author_email, author_date,
              committer, committer_email, committer_date
    """
    # Get commit message
    result = run_git_command(
        ['git', 'log', '-1', '--format=%B', commit_hash],
        cwd=repo_path,
        operation_description="Failed to get commit info"
    )

    if result is None:
        return None

    message = result.stdout.rstrip('\n')

    # Get author info
    result = run_git_command(
        ['git', 'log', '-1', '--format=%an%n%ae%n%aI', commit_hash],
        cwd=repo_path,
        operation_description="Failed to get commit author info"
    )

    if result is None:
        return None

    lines = result.stdout.strip().split('\n')
    author = lines[0]
    author_email = lines[1]
    author_date = lines[2]

    # Get committer info
    result = run_git_command(
        ['git', 'log', '-1', '--format=%cn%n%ce%n%cI', commit_hash],
        cwd=repo_path,
        operation_description="Failed to get commit committer info"
    )

    if result is None:
        return None

    lines = result.stdout.strip().split('\n')
    committer = lines[0]
    committer_email = lines[1]
    committer_date = lines[2]

    return {
        'message': message,
        'author': author,
        'author_email': author_email,
        'author_date': author_date,
        'committer': committer,
        'committer_email': committer_email,
        'committer_date': committer_date
    }


def validate_metadata_integrity(metadata_path, metadata_version, quiet=False):
    """
    Validate metadata file integrity and version.

    Performs:
    - Manifest version validation
    - Checksum verification

    Args:
        metadata_path: Path to metadata file
        metadata_version: Manifest version from metadata
        quiet: Whether to suppress output

    Returns:
        bool: True if all validations pass, False otherwise
    """
    if not validate_manifest_version(metadata_version, quiet):
        return False

    if not verify_checksum(metadata_path, quiet):
        return False

    return True


def validate_repositories(original_repo_path, ephemeral_path, quiet=False):
    """
    Validate that both repositories are ready for synchronization.

    Performs:
    - Original repository existence and validity
    - Uncommitted changes check in original repository
    - Uncommitted changes check in ephemeral repository

    Args:
        original_repo_path: Path to original repository
        ephemeral_path: Path to ephemeral repository
        quiet: Whether to suppress output

    Returns:
        bool: True if all validations pass, False otherwise
    """
    original_path = Path(original_repo_path)

    if not validate_original_repo(original_repo_path, quiet):
        return False

    if not detect_uncommitted_changes(original_path, "Original repository", quiet):
        return False

    if not detect_uncommitted_changes(ephemeral_path, "Ephemeral repository", quiet):
        return False

    return True


def validate_sync_safety(original_repo_path, ephemeral_path, metadata, quiet=False):
    """
    Validate that synchronization can proceed safely.

    Performs:
    - Branch match verification (if source_branch in metadata)
    - Baseline commit verification
    - Initial commit content verification
    - Out-of-scope files detection

    Args:
        original_repo_path: Path to original repository
        ephemeral_path: Path to ephemeral repository
        metadata: Parsed metadata dictionary
        quiet: Whether to suppress output

    Returns:
        bool: True if all validations pass, False otherwise
    """
    # Verify branch matches if source_branch is in metadata
    if 'source_branch' in metadata:
        if not verify_branch_match(original_repo_path, metadata['source_branch'], quiet):
            return False
    else:
        # If source_branch is not in metadata, warn and prompt the user.
        branch_name = get_current_branch(Path(original_repo_path))
        sys.stderr.write(f"Warning: Metadata does not contain source branch information.\n")
        sys.stderr.write(f"This can happen if the ephemeral repo was created with an older script version.\n")

        if branch_name:
            sys.stderr.write(f"The destination repository is currently on branch: '{branch_name}'.\n")
            sys.stderr.write(f"Proceed with syncing to this branch? [y/N]: ")
            sys.stderr.flush()
            choice = sys.stdin.readline().strip().lower()
            if choice not in ['y', 'yes']:
                sys.stderr.write("Aborted by user.\n")
                return False
        else:
            # Destination is in detached HEAD state, which is an error condition.
            sys.stderr.write(f"Error: Destination repository is in a detached HEAD state.\n")
            sys.stderr.write(f"Cannot proceed without a target branch.\n")
            return False

    if not verify_baseline_commit(original_repo_path, metadata['baseline_commit'], quiet):
        return False

    if not verify_initial_commit_content(
        ephemeral_path,
        original_repo_path,
        metadata['baseline_commit'],
        metadata['subset']['paths'],
        quiet
    ):
        return False

    if not detect_outofscope_files(
        ephemeral_path,
        metadata['subset']['paths'],
        original_repo_path,
        quiet
    ):
        return False

    return True


def display_sync_plan(original_repo_path, branch_name, commits, ephemeral_path, quiet=False):
    """
    Display what will be synced and ask for confirmation.

    Args:
        original_repo_path: Path to original repository
        branch_name: Name of target branch
        commits: List of commit hashes to replay
        ephemeral_path: Path to ephemeral repository
        quiet: Whether to suppress output
    """
    if quiet:
        return

    print(f"\n{'='*60}")
    print(f"SYNCHRONIZATION PLAN")
    print(f"{'='*60}")
    print(f"Source: {ephemeral_path}")
    print(f"Destination: {original_repo_path}")
    print(f"Target branch: {branch_name if branch_name else '(detached HEAD)'}")
    print(f"Commits to replay: {len(commits)}")

    if commits:
        print(f"\nCommits:")
        for i, commit_hash in enumerate(commits, 1):
            info = get_commit_info(ephemeral_path, commit_hash)
            if info:
                # Truncate message to first line
                message_line = info['message'].split('\n')[0]
                if len(message_line) > 60:
                    message_line = message_line[:57] + '...'
                print(f"  {i}. {commit_hash[:8]} - {message_line}")

    print(f"{'='*60}")


def prompt_confirmation():
    """
    Ask user to confirm synchronization.

    Returns:
        bool: True if user confirms, False otherwise
    """
    sys.stdout.write("\nProceed with synchronization? [y/N]: ")
    sys.stdout.flush()

    choice = sys.stdin.readline().strip().lower()

    if choice in ['y', 'yes']:
        return True
    else:
        print("Aborted by user.")
        return False


def get_commit_changes(repo_path, commit_hash):
    """
    Get the changes introduced by a commit as a patch.

    Args:
        repo_path: Repository path
        commit_hash: Commit hash

    Returns:
        str: Patch content, or None on error
    """
    result = run_git_command(
        ['git', 'format-patch', '-1', '--stdout', commit_hash],
        cwd=repo_path,
        operation_description="Failed to get commit changes"
    )

    return result.stdout if result else None


def apply_commit(original_repo_path, patch_content, commit_info, quiet=False):
    """
    Apply a commit to the original repository.

    Args:
        original_repo_path: Path to original repository
        patch_content: Patch content to apply
        commit_info: Commit metadata (message, author, dates, etc.)
        quiet: Whether to suppress output

    Returns:
        bool: True on success, False on error
    """
    # Apply the patch
    result = run_git_command(
        ['git', 'am', '--keep-cr'],
        cwd=original_repo_path,
        check_returncode=False,
        input_data=patch_content
    )

    if result is None or result.returncode != 0:
        # Try to abort the am operation
        run_git_command(
            ['git', 'am', '--abort'],
            cwd=original_repo_path,
            check_returncode=False
        )

        sys.stderr.write(f"Error: Failed to apply commit\n")
        if result and result.stderr:
            sys.stderr.write(f"{result.stderr}\n")
        return False

    if not quiet:
        message_line = commit_info['message'].split('\n')[0]
        print(f"  ✓ Applied: {message_line[:60]}")

    return True


def replay_commits(commits, ephemeral_path, original_repo_path, quiet=False):
    """
    Replay commits from ephemeral repository to original repository.

    Args:
        commits: List of commit hashes to replay
        ephemeral_path: Path to ephemeral repository
        original_repo_path: Path to original repository
        quiet: Whether to suppress output

    Returns:
        bool: True on success, False on error
    """
    if not commits:
        if not quiet:
            print("No commits to replay.")
        return True

    if not quiet:
        print(f"\nReplaying {len(commits)} commit(s)...")

    original_path = Path(original_repo_path)

    for i, commit_hash in enumerate(commits, 1):
        # Get commit info
        commit_info = get_commit_info(ephemeral_path, commit_hash)
        if commit_info is None:
            sys.stderr.write(f"\nError: Failed to get info for commit {commit_hash}\n")
            sys.stderr.write(f"Sync aborted after {i-1} of {len(commits)} commits.\n")
            return False

        # Get commit changes as patch
        patch_content = get_commit_changes(ephemeral_path, commit_hash)
        if patch_content is None:
            sys.stderr.write(f"\nError: Failed to get changes for commit {commit_hash}\n")
            sys.stderr.write(f"Sync aborted after {i-1} of {len(commits)} commits.\n")
            return False

        # Apply commit
        if not apply_commit(original_path, patch_content, commit_info, quiet):
            sys.stderr.write(f"\nSync aborted after {i-1} of {len(commits)} commits.\n")
            sys.stderr.write(f"This may be due to a merge conflict.\n")
            return False

    if not quiet:
        print(f"✓ Successfully replayed all {len(commits)} commit(s)")

    return True


def main():
    """
    Main entry point for the sync script.
    """
    # Set up signal handler for Control-C
    signal.signal(signal.SIGINT, handle_sigint)

    # Parse arguments
    args = parse_arguments()
    if args is None:
        sys.exit(1)

    # Determine ephemeral repository path (source)
    if args.source:
        ephemeral_path = resolve_path(args.source)
    else:
        ephemeral_path = Path.cwd()

    quiet = args.quiet
    dry_run = args.dry_run
    force = args.force

    if dry_run and not quiet:
        print("=== DRY RUN MODE - No changes will be made ===\n")

    # Locate and parse metadata
    metadata_path = locate_metadata(ephemeral_path, args.metadata)
    if metadata_path is None:
        sys.exit(1)

    metadata = parse_metadata(metadata_path, quiet)
    if metadata is None:
        sys.exit(1)

    # Determine the destination repository path
    if args.destination:
        # Use the user-provided destination as an override
        original_repo_path = resolve_path(args.destination)
        if not quiet:
            print(f"✓ Using destination override: {original_repo_path}")
    else:
        # Use the destination from the metadata file
        original_repo_path = resolve_path(metadata['original_repo_path'])

    # Validate metadata integrity
    if not validate_metadata_integrity(metadata_path, metadata['manifest_version'], quiet):
        sys.exit(1)

    # Validate repositories
    if not validate_repositories(original_repo_path, ephemeral_path, quiet):
        sys.exit(1)

    # Get current branch name
    original_path = Path(original_repo_path)
    branch_name = get_current_branch(original_path)
    if branch_name and not quiet:
        print(f"✓ Target branch: {branch_name}")

    # Validate sync safety
    if not validate_sync_safety(original_repo_path, ephemeral_path, metadata, quiet):
        sys.exit(1)

    # Get commits to replay
    commits = get_commits_to_replay(ephemeral_path)
    if commits is None:
        sys.exit(1)

    # Display sync plan
    display_sync_plan(original_repo_path, branch_name, commits, ephemeral_path, quiet)

    if dry_run:
        print(f"\n=== DRY RUN SUMMARY ===")
        print(f"Would create temporary branch: {branch_name}_temp_<timestamp>")
        print(f"Would replay {len(commits)} commit(s) to temporary branch")
        print(f"Would merge temporary branch into {branch_name}")
        print(f"Would delete temporary branch")
        print(f"No changes made (dry run).")
        sys.exit(0)

    # Ask for confirmation unless --force
    if not force:
        if not prompt_confirmation():
            sys.exit(1)

    # Use context manager for temporary branch operations
    sync_was_successful = False
    try:
        with TemporaryBranch(original_path, branch_name, quiet) as temp_branch:
            # Replay commits on temporary branch
            if not quiet:
                print()

            sync_was_successful = replay_commits(commits, ephemeral_path, original_path, quiet)

            if sync_was_successful:
                # Mark success so context manager knows to merge
                temp_branch.mark_success()
            else:
                sys.stderr.write(f"\nSync failed during commit replay.\n")
                # The 'with' block will now exit, and the context manager's
                # __exit__ method will handle cleanup for the failure case.

    except RuntimeError as e:
        sys.stderr.write(f"Error: {e}\n")
        sync_was_successful = False
    except Exception as e:
        sys.stderr.write(f"Unexpected error: {e}\n")
        sync_was_successful = False

    if sync_was_successful:
        # Success!
        if not quiet:
            print(f"\n{'='*60}")
            print(f"✓ Successfully synchronized ephemeral repository!")
            print(f"{'='*60}")
            print(f"Replayed commits: {len(commits)}")
            print(f"Original repository: {original_repo_path}")
            print(f"Branch: {branch_name if branch_name else '(detached HEAD)'}")
            print(f"\nThe ephemeral repository can now be safely deleted.")
        sys.exit(0)
    else:
        # The context manager will have already handled cleanup prompts.
        # We just need to exit with an error code.
        sys.exit(1)


if __name__ == '__main__':
    main()
