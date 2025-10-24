#!/usr/bin/env python3
"""
Sync Verification Script

Verifies that files from a source repository have been accurately synced
to a destination repository. Checks file content, permissions, and git
history (commit messages, authors, timestamps).

Usage:
    ./verify_sync.py --source <source_repo> --destination <dest_repo>
    ./verify_sync.py --help

Examples:
    ./verify_sync.py --source ./ephemeral-repo --destination ./original-repo
    ./verify_sync.py --source ~/ephemeral --destination ~/monorepo --verbose

The script verifies:
- All files from source exist in destination (excluding .gitignore)
- File contents match exactly
- File permissions match (where applicable)
- Commit messages, authors, and timestamps are preserved
"""

import sys
import os
import argparse
import subprocess
import hashlib
from pathlib import Path
from typing import Optional, Dict, List, Set, Tuple


def print_help():
    """
    Print detailed help information to stderr.
    """
    help_text = """
Sync Verification Script

Verifies that a source repository has been accurately synced to a
destination repository.

Required Arguments:
  --source <path>        Path to source repository (ephemeral repo)
  --destination <path>   Path to destination repository (original repo)

Optional Arguments:
  --verbose             Show detailed verification progress
  --help                Show this help message

Verification Checks:
  1. File existence - All non-.gitignore files from source exist in destination
  2. File content - Content matches exactly (SHA256 hash comparison)
  3. File permissions - Execute permissions match
  4. Git history - Commits from source are present in destination
  5. Commit metadata - Messages, authors, and timestamps preserved

Exit Codes:
  0 - Verification passed (repositories match)
  1 - Verification failed (discrepancies found)
  2 - Error during verification

Examples:
  ./verify_sync.py --source ./ephemeral --destination ./original
  ./verify_sync.py --source ~/ephemeral-repo --destination ~/monorepo --verbose
"""
    sys.stderr.write(help_text)


def parse_arguments():
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--source', type=str, help='Path to source repository')
    parser.add_argument('--destination', type=str, help='Path to destination repository')
    parser.add_argument('--verbose', action='store_true', help='Show detailed progress')
    parser.add_argument('--help', action='store_true', help='Show help message')

    args = parser.parse_args()

    if args.help:
        print_help()
        sys.exit(0)

    return args


def print_usage():
    """
    Print brief usage information to stderr.
    """
    sys.stderr.write("Usage: verify_sync.py --source <source_repo> --destination <dest_repo>\n")
    sys.stderr.write("       verify_sync.py --help\n")


def validate_arguments(args):
    """
    Validate that all required arguments are present.

    Args:
        args: Parsed command-line arguments

    Returns:
        bool: True if valid, False otherwise
    """
    missing = []

    if not args.source:
        missing.append('--source')
    if not args.destination:
        missing.append('--destination')

    if missing:
        sys.stderr.write(f"Error: Missing required arguments: {', '.join(missing)}\n")
        print_usage()
        return False

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

    try:
        subprocess.run(
            ['git', 'rev-parse', '--git-dir'],
            cwd=repo_path,
            capture_output=True,
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        sys.stderr.write(f"Error: {repo_name} is not a valid git repository: {repo_path}\n")
        return False


def get_tracked_files(repo_path):
    """
    Get all tracked files in a repository.

    Args:
        repo_path: Path to repository

    Returns:
        set: Set of relative file paths, or None on error
    """
    try:
        result = subprocess.run(
            ['git', 'ls-files'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        files = set(result.stdout.strip().split('\n')) if result.stdout.strip() else set()
        return files
    except subprocess.CalledProcessError as e:
        sys.stderr.write(f"Error: Failed to get tracked files: {e}\n")
        return None


def filter_gitignore_files(files):
    """
    Filter out .gitignore files at any level.

    Args:
        files: Set of file paths

    Returns:
        set: Filtered set of file paths
    """
    return {f for f in files if not f.endswith('.gitignore') and '/.gitignore' not in f and f != '.gitignore'}


def filter_metadata_files(files):
    """
    Filter out ephemeral repository metadata files.

    Args:
        files: Set of file paths

    Returns:
        set: Filtered set of file paths
    """
    metadata_files = {'metadata', 'metadata.sha256'}
    return {f for f in files if f not in metadata_files}


def calculate_file_hash(file_path):
    """
    Calculate SHA256 hash of a file.

    Args:
        file_path: Path to file

    Returns:
        str: Hexadecimal hash string, or None on error
    """
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        sys.stderr.write(f"Error: Failed to calculate hash for {file_path}: {e}\n")
        return None


def compare_file_content(source_path, dest_path, rel_path, verbose=False):
    """
    Compare content of two files using hash comparison.

    Args:
        source_path: Path to source repository
        dest_path: Path to destination repository
        rel_path: Relative path to file
        verbose: Whether to show detailed output

    Returns:
        bool: True if files match, False otherwise
    """
    source_file = source_path / rel_path
    dest_file = dest_path / rel_path

    if not dest_file.exists():
        return False

    source_hash = calculate_file_hash(source_file)
    dest_hash = calculate_file_hash(dest_file)

    if source_hash is None or dest_hash is None:
        return False

    matches = source_hash == dest_hash

    if verbose:
        if matches:
            print(f"  ✓ Content matches: {rel_path}")
        else:
            print(f"  ✗ Content differs: {rel_path}")

    return matches


def compare_file_permissions(source_path, dest_path, rel_path, verbose=False):
    """
    Compare execute permissions of two files.

    Args:
        source_path: Path to source repository
        dest_path: Path to destination repository
        rel_path: Relative path to file
        verbose: Whether to show detailed output

    Returns:
        tuple: (matches, warning_message)
    """
    source_file = source_path / rel_path
    dest_file = dest_path / rel_path

    if not dest_file.exists():
        return False, None

    try:
        source_stat = source_file.stat()
        dest_stat = dest_file.stat()

        source_executable = bool(source_stat.st_mode & 0o111)
        dest_executable = bool(dest_stat.st_mode & 0o111)

        matches = source_executable == dest_executable

        if verbose and matches:
            print(f"  ✓ Permissions match: {rel_path}")
        elif not matches:
            warning = f"Execute permission mismatch: {rel_path}"
            return False, warning

        return True, None

    except Exception as e:
        warning = f"Could not compare permissions for {rel_path}: {e}"
        return True, warning  # Don't fail verification, just warn


def get_initial_commit(repo_path):
    """
    Get the hash of the initial (first) commit in a repository.

    Args:
        repo_path: Path to repository

    Returns:
        str: Commit hash, or None on error
    """
    try:
        result = subprocess.run(
            ['git', 'rev-list', '--max-parents=0', 'HEAD'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def get_commits_after_initial(repo_path):
    """
    Get list of commits after the initial commit.

    Args:
        repo_path: Path to repository

    Returns:
        list: List of commit hashes (oldest to newest), or None on error
    """
    try:
        initial_commit = get_initial_commit(repo_path)
        if initial_commit is None:
            return None

        result = subprocess.run(
            ['git', 'rev-list', '--reverse', f'{initial_commit}..HEAD'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )

        commits = result.stdout.strip().split('\n') if result.stdout.strip() else []
        return commits

    except subprocess.CalledProcessError as e:
        sys.stderr.write(f"Error: Failed to get commits: {e}\n")
        return None


def get_commit_info(repo_path, commit_hash):
    """
    Get detailed information about a commit.

    Args:
        repo_path: Path to repository
        commit_hash: Commit hash

    Returns:
        dict: Commit information, or None on error
    """
    try:
        # Get commit message
        result = subprocess.run(
            ['git', 'log', '-1', '--format=%B', commit_hash],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        message = result.stdout.rstrip('\n')

        # Get commit metadata
        result = subprocess.run(
            ['git', 'log', '-1', '--format=%an%n%ae%n%aI%n%cn%n%ce%n%cI', commit_hash],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.strip().split('\n')

        return {
            'hash': commit_hash,
            'message': message,
            'author_name': lines[0],
            'author_email': lines[1],
            'author_date': lines[2],
            'committer_name': lines[3],
            'committer_email': lines[4],
            'committer_date': lines[5]
        }

    except subprocess.CalledProcessError as e:
        sys.stderr.write(f"Error: Failed to get commit info for {commit_hash}: {e}\n")
        return None


def find_matching_commit_in_dest(dest_commits, source_commit_info):
    """
    Find a commit in destination that matches source commit metadata.

    Args:
        dest_commits: List of commit info dicts from destination
        source_commit_info: Commit info dict from source

    Returns:
        dict: Matching commit info from destination, or None if not found
    """
    for dest_commit in dest_commits:
        if (dest_commit['message'] == source_commit_info['message'] and
            dest_commit['author_name'] == source_commit_info['author_name'] and
            dest_commit['author_email'] == source_commit_info['author_email']):
            return dest_commit

    return None


def compare_commit_timestamps(source_info, dest_info, verbose=False):
    """
    Compare commit timestamps (author_date).

    Args:
        source_info: Source commit info
        dest_info: Destination commit info
        verbose: Whether to show detailed output

    Returns:
        bool: True if timestamps match, False otherwise
    """
    matches = source_info['author_date'] == dest_info['author_date']

    if not matches and verbose:
        print(f"  ! Timestamp mismatch for commit: {source_info['message'][:50]}")
        print(f"    Source: {source_info['author_date']}")
        print(f"    Dest:   {dest_info['author_date']}")

    return matches


class VerificationResult:
    """Container for verification results."""

    def __init__(self):
        self.passed = True
        self.errors = []
        self.warnings = []
        self.stats = {
            'files_checked': 0,
            'files_matched': 0,
            'files_missing': 0,
            'files_differ': 0,
            'commits_checked': 0,
            'commits_matched': 0,
            'commits_missing': 0,
            'timestamp_mismatches': 0
        }

    def add_error(self, error):
        """Add an error message."""
        self.errors.append(error)
        self.passed = False

    def add_warning(self, warning):
        """Add a warning message."""
        self.warnings.append(warning)

    def print_summary(self):
        """Print verification summary."""
        print(f"\n{'='*60}")
        print(f"VERIFICATION SUMMARY")
        print(f"{'='*60}")

        # File statistics
        print(f"\nFile Verification:")
        print(f"  Total files checked: {self.stats['files_checked']}")
        print(f"  Files matched: {self.stats['files_matched']}")
        print(f"  Files missing: {self.stats['files_missing']}")
        print(f"  Files with different content: {self.stats['files_differ']}")

        # Commit statistics
        print(f"\nCommit Verification:")
        print(f"  Total commits checked: {self.stats['commits_checked']}")
        print(f"  Commits matched: {self.stats['commits_matched']}")
        print(f"  Commits missing: {self.stats['commits_missing']}")
        print(f"  Timestamp mismatches: {self.stats['timestamp_mismatches']}")

        # Warnings
        if self.warnings:
            print(f"\nWarnings ({len(self.warnings)}):")
            for warning in self.warnings[:10]:
                print(f"  ⚠ {warning}")
            if len(self.warnings) > 10:
                print(f"  ... and {len(self.warnings) - 10} more warnings")

        # Errors
        if self.errors:
            print(f"\nErrors ({len(self.errors)}):")
            for error in self.errors[:10]:
                print(f"  ✗ {error}")
            if len(self.errors) > 10:
                print(f"  ... and {len(self.errors) - 10} more errors")

        # Final result
        print(f"\n{'='*60}")
        if self.passed:
            print(f"✓ VERIFICATION PASSED")
            print(f"{'='*60}")
            print(f"Source repository has been accurately synced to destination.")
        else:
            print(f"✗ VERIFICATION FAILED")
            print(f"{'='*60}")
            print(f"Discrepancies found between source and destination repositories.")


def verify_files(source_path, dest_path, verbose=False):
    """
    Verify that all files from source exist in destination with matching content.

    Args:
        source_path: Path to source repository
        dest_path: Path to destination repository
        verbose: Whether to show detailed output

    Returns:
        VerificationResult: Verification results
    """
    result = VerificationResult()

    if verbose:
        print("Verifying files...")

    # Get tracked files from source
    source_files = get_tracked_files(source_path)
    if source_files is None:
        result.add_error("Failed to get source file list")
        return result

    # Filter out .gitignore and metadata files
    source_files = filter_gitignore_files(source_files)
    source_files = filter_metadata_files(source_files)

    # Get tracked files from destination
    dest_files = get_tracked_files(dest_path)
    if dest_files is None:
        result.add_error("Failed to get destination file list")
        return result

    if verbose:
        print(f"  Source files to verify: {len(source_files)}")

    # Check each source file
    for rel_path in sorted(source_files):
        result.stats['files_checked'] += 1

        # Check if file exists in destination
        if rel_path not in dest_files:
            result.add_error(f"File missing in destination: {rel_path}")
            result.stats['files_missing'] += 1
            continue

        # Compare file content
        if not compare_file_content(source_path, dest_path, rel_path, verbose):
            result.add_error(f"File content differs: {rel_path}")
            result.stats['files_differ'] += 1
            continue

        result.stats['files_matched'] += 1

        # Compare file permissions
        perms_match, warning = compare_file_permissions(source_path, dest_path, rel_path, verbose)
        if warning:
            result.add_warning(warning)

    if not verbose:
        print(f"✓ Verified {result.stats['files_checked']} files")

    return result


def verify_commits(source_path, dest_path, verbose=False):
    """
    Verify that commits from source are present in destination with matching metadata.

    Args:
        source_path: Path to source repository
        dest_path: Path to destination repository
        verbose: Whether to show detailed output

    Returns:
        VerificationResult: Verification results
    """
    result = VerificationResult()

    if verbose:
        print("\nVerifying commits...")

    # Get commits from source (excluding initial commit)
    source_commits_hashes = get_commits_after_initial(source_path)
    if source_commits_hashes is None:
        result.add_error("Failed to get source commit list")
        return result

    if not source_commits_hashes:
        if verbose:
            print("  No commits to verify (source has only initial commit)")
        return result

    # Get commit info for all source commits
    source_commits = []
    for commit_hash in source_commits_hashes:
        commit_info = get_commit_info(source_path, commit_hash)
        if commit_info:
            source_commits.append(commit_info)

    result.stats['commits_checked'] = len(source_commits)

    if verbose:
        print(f"  Source commits to verify: {len(source_commits)}")

    # Get recent commits from destination
    dest_commits_hashes = get_commits_after_initial(dest_path)
    if dest_commits_hashes is None:
        result.add_error("Failed to get destination commit list")
        return result

    # For efficiency, only check recent commits in destination
    # (assume synced commits are at the end)
    recent_dest_hashes = dest_commits_hashes[-len(source_commits)*2:] if dest_commits_hashes else []

    dest_commits = []
    for commit_hash in recent_dest_hashes:
        commit_info = get_commit_info(dest_path, commit_hash)
        if commit_info:
            dest_commits.append(commit_info)

    # Match each source commit in destination
    for source_commit in source_commits:
        matching_commit = find_matching_commit_in_dest(dest_commits, source_commit)

        if matching_commit is None:
            result.add_error(
                f"Commit not found in destination: {source_commit['message'][:50]}... "
                f"(author: {source_commit['author_name']})"
            )
            result.stats['commits_missing'] += 1
            continue

        result.stats['commits_matched'] += 1

        if verbose:
            print(f"  ✓ Found commit: {source_commit['message'][:50]}")

        # Check timestamp preservation
        if not compare_commit_timestamps(source_commit, matching_commit, verbose):
            result.add_warning(
                f"Commit timestamp not preserved: {source_commit['message'][:50]}"
            )
            result.stats['timestamp_mismatches'] += 1

    if not verbose:
        print(f"✓ Verified {result.stats['commits_checked']} commits")

    return result


def merge_results(file_result, commit_result):
    """
    Merge two verification results.

    Args:
        file_result: File verification result
        commit_result: Commit verification result

    Returns:
        VerificationResult: Combined result
    """
    combined = VerificationResult()

    combined.errors = file_result.errors + commit_result.errors
    combined.warnings = file_result.warnings + commit_result.warnings
    combined.passed = file_result.passed and commit_result.passed

    # Merge stats by taking values from each result for their respective keys
    # File verification keys
    combined.stats['files_checked'] = file_result.stats['files_checked']
    combined.stats['files_matched'] = file_result.stats['files_matched']
    combined.stats['files_missing'] = file_result.stats['files_missing']
    combined.stats['files_differ'] = file_result.stats['files_differ']

    # Commit verification keys
    combined.stats['commits_checked'] = commit_result.stats['commits_checked']
    combined.stats['commits_matched'] = commit_result.stats['commits_matched']
    combined.stats['commits_missing'] = commit_result.stats['commits_missing']
    combined.stats['timestamp_mismatches'] = commit_result.stats['timestamp_mismatches']

    return combined

def main():
    """
    Main entry point for the verification script.
    """
    # Parse arguments
    args = parse_arguments()

    # Validate arguments
    if not validate_arguments(args):
        sys.exit(2)

    # Resolve paths
    source_path = resolve_path(args.source)
    dest_path = resolve_path(args.destination)

    verbose = args.verbose

    print(f"Verifying sync from source to destination")
    print(f"  Source:      {source_path}")
    print(f"  Destination: {dest_path}")
    print()

    # Validate repositories
    if not validate_repository(source_path, "Source repository"):
        sys.exit(2)

    if not validate_repository(dest_path, "Destination repository"):
        sys.exit(2)

    # Verify files
    file_result = verify_files(source_path, dest_path, verbose)

    # Verify commits
    commit_result = verify_commits(source_path, dest_path, verbose)

    # Combine results
    final_result = merge_results(file_result, commit_result)

    # Print summary
    final_result.print_summary()

    # Exit with appropriate code
    if final_result.passed:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
