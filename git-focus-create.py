#!/usr/bin/env python3
"""
Ephemeral Repository Creation Script

Creates an isolated ephemeral git repository containing only a specified
subset of files from a source monorepo. Generates metadata and checksum
files for later synchronization.

Usage:
    ./git-focus-create.py --source <repo> --subset <file> --destination <dir>
    ./git-focus-create.py --help

Examples:
    ./git-focus-create.py --source ~/monorepo --subset subset.txt --destination ./ephemeral
    ./git-focus-create.py --source /path/to/repo --subset paths.txt --destination ./work --dry-run
    ./git-focus-create.py --help

For more information, see ephemeral-repo-create-and-sync-specifications.md
"""

import sys
import os
import argparse
import signal
import hashlib
import shutil
import subprocess
import glob as globlib
from pathlib import Path
from datetime import datetime, timezone
import stat

# Manifest version for metadata compatibility
MANIFEST_VERSION = "1.0"

# Default metadata filename
DEFAULT_METADATA_FILENAME = ".git-focus-metadata"


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
    sys.stderr.write("Usage: git-focus-create.py --source <repo> --subset <file> --destination <dir>\n")
    sys.stderr.write("       git-focus-create.py --help\n")


def print_help():
    """
    Print detailed help information to stderr.
    """
    help_text = f"""
Ephemeral Repository Creation Script

Creates an isolated ephemeral git repository containing only a specified
subset of files from a source monorepo.

Required Arguments:
  --source <path>        Path to the original git repository
  --subset <path>        Path to subset definition file (one path per line)
  --destination <dir>    Directory where ephemeral repository will be created

Optional Arguments:
  --metadata <path>      Custom metadata filename (default: {DEFAULT_METADATA_FILENAME})
  --dry-run             Show what would be done without doing it
  --quiet               Suppress warnings and non-error output
  --help                Show this help message

Subset Definition File Format:
  - One path per line (relative to repository root)
  - Lines starting with # are comments
  - Blank lines are ignored
  - Supports glob patterns: *, foo/*, foo/**/*.py
  - Directories will recursively include all files

Examples:
  ./git-focus-create.py --source ~/monorepo --subset subset.txt --destination ./ephemeral
  ./git-focus-create.py --source /path/to/repo --subset paths.txt --destination ./work --dry-run

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
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--source', type=str, help='Path to source repository')
    parser.add_argument('--subset', type=str, help='Path to subset definition file')
    parser.add_argument('--destination', type=str, help='Destination directory for ephemeral repo')
    parser.add_argument('--metadata', type=str, default=DEFAULT_METADATA_FILENAME,
                       help='Custom metadata filename')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done')
    parser.add_argument('--quiet', action='store_true', help='Suppress warnings and non-error output')
    parser.add_argument('--help', action='store_true', help='Show help message')

    args = parser.parse_args()

    if args.help:
        print_help()
        sys.exit(0)

    return args


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
    if not args.subset:
        missing.append('--subset')
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


def validate_source_repo(source_path, quiet=False):
    """
    Validate that the source path is a git repository.

    Args:
        source_path: Path to validate
        quiet: Whether to suppress output

    Returns:
        bool: True if valid git repository, False otherwise
    """
    git_dir = source_path / '.git'

    if not source_path.exists():
        sys.stderr.write(f"Error: Source path does not exist: {source_path}\n")
        return False

    if not source_path.is_dir():
        sys.stderr.write(f"Error: Source path is not a directory: {source_path}\n")
        return False

    if not git_dir.exists():
        sys.stderr.write(f"Error: Source path is not a git repository (no .git directory): {source_path}\n")
        return False

    # Verify it's actually a valid git repo by running a git command
    try:
        result = subprocess.run(
            ['git', 'rev-parse', '--git-dir'],
            cwd=source_path,
            capture_output=True,
            text=True,
            check=True
        )
        if not quiet:
            print(f"✓ Validated source repository: {source_path}")
        return True
    except subprocess.CalledProcessError:
        sys.stderr.write(f"Error: Source path is not a valid git repository: {source_path}\n")
        return False


def get_current_branch(source_path):
    """
    Get the current branch name of the source repository.

    Args:
        source_path: Source repository path

    Returns:
        str: Branch name, or None if detached HEAD or error
    """
    try:
        result = subprocess.run(
            ['git', 'symbolic-ref', '--short', 'HEAD'],
            cwd=source_path,
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode == 0:
            branch = result.stdout.strip()
            return branch if branch else None

        return None

    except Exception as e:
        sys.stderr.write(f"Error: Failed to get current branch: {e}\n")
        return None


def get_current_commit(source_path):
    """
    Get the current HEAD commit hash.

    Args:
        source_path: Source repository path

    Returns:
        str: Commit hash, or None on error
    """
    try:
        result = subprocess.run(
            ['git', 'rev-parse', 'HEAD'],
            cwd=source_path,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        sys.stderr.write(f"Error: Failed to get current commit: {e}\n")
        return None


def prompt_detached_head_warning(current_commit):
    """
    Prompt user about proceeding with detached HEAD state.

    Args:
        current_commit: Current commit hash

    Returns:
        bool: True if user wants to proceed, False otherwise
    """
    sys.stderr.write(f"\n{'='*60}\n")
    sys.stderr.write(f"WARNING: DETACHED HEAD DETECTED\n")
    sys.stderr.write(f"{'='*60}\n\n")
    sys.stderr.write(f"The source repository is currently in a detached HEAD state.\n")
    sys.stderr.write(f"This means HEAD points to a commit, not a branch.\n\n")
    sys.stderr.write(f"Current commit: {current_commit}\n")
    sys.stderr.write(f"Branch: (none - detached HEAD)\n\n")
    sys.stderr.write(f"Creating an ephemeral repository from detached HEAD is NOT\n")
    sys.stderr.write(f"recommended because:\n\n")
    sys.stderr.write(f"1. Syncing back will place commits in detached HEAD state\n")
    sys.stderr.write(f"2. These commits can be easily lost if you switch branches\n")
    sys.stderr.write(f"3. There is no branch reference to track your work\n\n")
    sys.stderr.write(f"RECOMMENDED ACTIONS:\n\n")
    sys.stderr.write(f"Option A: Create a branch first (recommended)\n")
    sys.stderr.write(f"  cd {os.getcwd()}\n")
    sys.stderr.write(f"  git checkout -b feature-branch\n")
    sys.stderr.write(f"  # Then run git-focus-create.py again\n\n")
    sys.stderr.write(f"Option B: Checkout an existing branch\n")
    sys.stderr.write(f"  cd {os.getcwd()}\n")
    sys.stderr.write(f"  git checkout main\n")
    sys.stderr.write(f"  # Then run git-focus-create.py again\n\n")
    sys.stderr.write(f"Option C: Proceed anyway (advanced users only)\n")
    sys.stderr.write(f"  - You will need to manually create a branch after sync\n")
    sys.stderr.write(f"  - Synced commits will be in detached HEAD state\n")
    sys.stderr.write(f"  - Risk of losing work if you don't create a branch\n\n")
    sys.stderr.write(f"Do you want to proceed anyway? [y/N]: ")
    sys.stderr.flush()

    choice = sys.stdin.readline().strip().lower()

    if choice in ['y', 'yes']:
        sys.stderr.write(f"\nProceeding with detached HEAD (user confirmed).\n")
        sys.stderr.write(f"WARNING: Remember to create a branch after syncing!\n\n")
        return True
    else:
        sys.stderr.write(f"\nAborted by user.\n")
        return False


def check_branch_state(source_path, quiet=False):
    """
    Check the branch state of the source repository and handle detached HEAD.

    Args:
        source_path: Source repository path
        quiet: Whether to suppress output

    Returns:
        tuple: (branch_name or None, commit_hash) or (None, None) if user aborts
    """
    # Get current commit
    current_commit = get_current_commit(source_path)
    if current_commit is None:
        return None, None

    # Get current branch
    current_branch = get_current_branch(source_path)

    if current_branch is None:
        # Detached HEAD state - prompt user
        if not prompt_detached_head_warning(current_commit):
            return None, None

        # User chose to proceed with detached HEAD
        return None, current_commit
    else:
        # Normal branch state
        if not quiet:
            print(f"✓ Source branch: {current_branch}")
        return current_branch, current_commit


def validate_destination(dest_path):
    """
    Validate that the destination does not already exist.

    Args:
        dest_path: Destination path to check

    Returns:
        bool: True if destination is available, False otherwise
    """
    if dest_path.exists():
        sys.stderr.write(f"Error: Destination directory already exists: {dest_path}\n")
        return False

    return True


def parse_subset_file(subset_path, quiet=False):
    """
    Parse the subset definition file and return list of path specifications.

    Args:
        subset_path: Path to subset definition file
        quiet: Whether to suppress output

    Returns:
        list: List of path specifications (may include globs), or None on error
    """
    if not subset_path.exists():
        sys.stderr.write(f"Error: Subset definition file not found: {subset_path}\n")
        return None

    path_specs = []

    try:
        with open(subset_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                # Remove leading/trailing whitespace
                line = line.strip()

                # Skip comments and blank lines
                if not line or line.startswith('#'):
                    continue

                path_specs.append(line)

        if not quiet:
            print(f"✓ Parsed subset definition: {len(path_specs)} path specification(s)")

        return path_specs

    except Exception as e:
        sys.stderr.write(f"Error: Failed to read subset file {subset_path}: {e}\n")
        return None


def expand_globs(path_specs, source_path, quiet=False):
    """
    Expand glob patterns in path specifications to concrete paths.

    Args:
        path_specs: List of path specifications (may include globs)
        source_path: Source repository path
        quiet: Whether to suppress output

    Returns:
        list: List of concrete relative paths, or None on error
    """
    expanded_paths = set()

    for spec in path_specs:
        # Check if this is a glob pattern
        if '*' in spec or '?' in spec or '[' in spec:
            # Use glob to expand the pattern
            matches = list(source_path.glob(spec))

            if not matches:
                sys.stderr.write(f"Error: Glob pattern matched no files: {spec}\n")
                return None

            for match in matches:
                # Convert to relative path from source_path
                try:
                    rel_path = match.relative_to(source_path)
                    expanded_paths.add(str(rel_path))
                except ValueError:
                    sys.stderr.write(f"Error: Matched path is outside source repository: {match}\n")
                    return None
        else:
            # Not a glob, just add as-is
            expanded_paths.add(spec)

    result = sorted(list(expanded_paths))

    if not quiet:
        print(f"✓ Expanded to {len(result)} concrete path(s)")

    return result


def validate_subset_paths(paths, source_path, quiet=False):
    """
    Validate that all subset paths exist and are tracked in git.

    Args:
        paths: List of relative paths to validate
        source_path: Source repository path
        quiet: Whether to suppress output

    Returns:
        bool: True if all paths are valid, False otherwise
    """
    for path_str in paths:
        full_path = source_path / path_str

        # Check if path exists
        if not full_path.exists():
            sys.stderr.write(f"Error: Subset path does not exist: {path_str}\n")
            return False

        # Check if path is tracked in git or ignored
        try:
            # Check if file is tracked
            result = subprocess.run(
                ['git', 'ls-files', '--error-unmatch', path_str],
                cwd=source_path,
                capture_output=True,
                text=True
            )

            # If it's a directory, git ls-files won't match it directly
            # So we need to check if it contains tracked files
            if result.returncode != 0 and full_path.is_dir():
                result = subprocess.run(
                    ['git', 'ls-files', path_str],
                    cwd=source_path,
                    capture_output=True,
                    text=True,
                    check=True
                )
                if not result.stdout.strip():
                    sys.stderr.write(f"Error: Directory contains no tracked files: {path_str}\n")
                    return False
            elif result.returncode != 0:
                sys.stderr.write(f"Error: Path is not tracked in git: {path_str}\n")
                return False

        except subprocess.CalledProcessError as e:
            sys.stderr.write(f"Error: Failed to check git status for path: {path_str}\n")
            return False

    if not quiet:
        print(f"✓ Validated {len(paths)} subset path(s)")

    return True


def check_uncommitted_changes(paths, source_path, quiet=False):
    """
    Check if any subset paths have uncommitted changes.

    Args:
        paths: List of relative paths to check
        source_path: Source repository path
        quiet: Whether to suppress output

    Returns:
        bool: True if no uncommitted changes, False otherwise
    """
    try:
        # Check for uncommitted changes in the subset paths
        for path_str in paths:
            result = subprocess.run(
                ['git', 'diff', '--name-only', 'HEAD', '--', path_str],
                cwd=source_path,
                capture_output=True,
                text=True,
                check=True
            )

            if result.stdout.strip():
                sys.stderr.write(f"Error: Subset path has uncommitted changes: {path_str}\n")
                sys.stderr.write(f"Modified files:\n{result.stdout}")
                return False

            # Also check for staged but uncommitted changes
            result = subprocess.run(
                ['git', 'diff', '--cached', '--name-only', '--', path_str],
                cwd=source_path,
                capture_output=True,
                text=True,
                check=True
            )

            if result.stdout.strip():
                sys.stderr.write(f"Error: Subset path has staged uncommitted changes: {path_str}\n")
                sys.stderr.write(f"Staged files:\n{result.stdout}")
                return False

        if not quiet:
            print(f"✓ No uncommitted changes in subset paths")

        return True

    except subprocess.CalledProcessError as e:
        sys.stderr.write(f"Error: Failed to check for uncommitted changes: {e}\n")
        return False


def detect_overlapping_paths(paths):
    """
    Detect if any path is a parent of another path in the list.

    Args:
        paths: List of relative path strings

    Returns:
        tuple: (bool, list) - (True if no overlaps, list of overlapping pairs)
    """
    overlaps = []

    for i, path1 in enumerate(paths):
        for j, path2 in enumerate(paths):
            if i >= j:
                continue

            p1 = Path(path1)
            p2 = Path(path2)

            # Check if p1 is parent of p2 or vice versa
            try:
                p2.relative_to(p1)
                overlaps.append((path1, path2))
            except ValueError:
                try:
                    p1.relative_to(p2)
                    overlaps.append((path2, path1))
                except ValueError:
                    pass

    if overlaps:
        sys.stderr.write("Error: Overlapping paths detected (parent and child both specified):\n")
        for parent, child in overlaps:
            sys.stderr.write(f"  Parent: {parent}\n  Child:  {child}\n")
        return False, overlaps

    return True, []


def get_baseline_commit(source_path):
    """
    Get the current HEAD commit hash of the source repository.

    Args:
        source_path: Source repository path

    Returns:
        str: Commit hash, or None on error
    """
    try:
        result = subprocess.run(
            ['git', 'rev-parse', 'HEAD'],
            cwd=source_path,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        sys.stderr.write(f"Error: Failed to get baseline commit: {e}\n")
        return None


def create_ephemeral_repo(dest_path, quiet=False):
    """
    Initialize a new git repository at the destination.

    Args:
        dest_path: Destination path for new repository
        quiet: Whether to suppress output

    Returns:
        bool: True on success, False on error
    """
    try:
        # Create destination directory
        dest_path.mkdir(parents=True, exist_ok=False)

        # Initialize git repository
        subprocess.run(
            ['git', 'init'],
            cwd=dest_path,
            capture_output=True,
            check=True
        )

        if not quiet:
            print(f"✓ Created ephemeral repository: {dest_path}")

        return True

    except subprocess.CalledProcessError as e:
        sys.stderr.write(f"Error: Failed to initialize git repository: {e}\n")
        return False
    except Exception as e:
        sys.stderr.write(f"Error: Failed to create destination directory: {e}\n")
        return False


def copy_file_with_attributes(src_path, dest_path, quiet=False):
    """
    Copy a file preserving attributes (permissions, timestamps, etc.).

    Args:
        src_path: Source file path
        dest_path: Destination file path
        quiet: Whether to suppress warnings

    Returns:
        bool: True on success, False on error
    """
    try:
        # Create parent directory if needed
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        # Copy file with metadata
        shutil.copy2(src_path, dest_path)

        # Try to preserve additional attributes
        try:
            src_stat = src_path.stat()
            os.chmod(dest_path, src_stat.st_mode)
        except Exception as e:
            if not quiet:
                sys.stderr.write(f"Warning: Could not preserve all attributes for {dest_path}: {e}\n")

        return True

    except Exception as e:
        sys.stderr.write(f"Error: Failed to copy file {src_path} to {dest_path}: {e}\n")
        return False


def copy_files_with_attributes(paths, source_path, dest_path, quiet=False):
    """
    Copy all subset files to the ephemeral repository, preserving attributes.

    Args:
        paths: List of relative paths to copy
        source_path: Source repository path
        dest_path: Destination repository path
        quiet: Whether to suppress output

    Returns:
        bool: True on success, False on error
    """
    files_copied = 0

    for path_str in paths:
        src = source_path / path_str
        dest = dest_path / path_str

        if src.is_file():
            # Skip .gitignore files
            if src.name == '.gitignore':
                if not quiet:
                    print(f"  Skipping: {path_str} (.gitignore)")
                continue

            if not copy_file_with_attributes(src, dest, quiet):
                return False
            files_copied += 1
            if not quiet:
                print(f"  Copied: {path_str}")

        elif src.is_dir():
            # Recursively copy directory
            for root, dirs, files in os.walk(src):
                root_path = Path(root)
                rel_root = root_path.relative_to(source_path)

                for filename in files:
                    # Skip .gitignore files
                    if filename == '.gitignore':
                        if not quiet:
                            print(f"  Skipping: {rel_root / filename} (.gitignore)")
                        continue

                    src_file = root_path / filename
                    dest_file = dest_path / rel_root / filename

                    if not copy_file_with_attributes(src_file, dest_file, quiet):
                        return False
                    files_copied += 1
                    if not quiet:
                        print(f"  Copied: {rel_root / filename}")

                # Create empty directories
                for dirname in dirs:
                    (dest_path / rel_root / dirname).mkdir(parents=True, exist_ok=True)

    if not quiet:
        print(f"✓ Copied {files_copied} file(s)")

    return True


def create_initial_commit(dest_path, quiet=False):
    """
    Create the initial commit in the ephemeral repository.

    Args:
        dest_path: Ephemeral repository path
        quiet: Whether to suppress output

    Returns:
        bool: True on success, False on error
    """
    try:
        # Add all files
        subprocess.run(
            ['git', 'add', '.'],
            cwd=dest_path,
            capture_output=True,
            check=True
        )

        # Create initial commit
        subprocess.run(
            ['git', 'commit', '-m', 'Initial checkin'],
            cwd=dest_path,
            capture_output=True,
            check=True
        )

        if not quiet:
            print(f"✓ Created initial commit")

        return True

    except subprocess.CalledProcessError as e:
        sys.stderr.write(f"Error: Failed to create initial commit: {e}\n")
        if e.stderr:
            sys.stderr.write(f"{e.stderr.decode()}\n")
        return False


def generate_session_id():
    """
    Generate a timestamp-based session ID.

    Returns:
        str: Session ID in format YYYYMMDD-HHMMSS
    """
    now = datetime.now(timezone.utc)
    return now.strftime("%Y%m%d-%H%M%S")


def generate_metadata(dest_path, metadata_filename, session_id, baseline_commit,
                      original_repo_path, subset_paths, source_branch=None, quiet=False):
    """
    Generate the metadata TOML file.

    Args:
        dest_path: Ephemeral repository path
        metadata_filename: Name of metadata file
        session_id: Session identifier
        baseline_commit: Baseline commit hash
        original_repo_path: Absolute path to original repository
        subset_paths: List of subset paths
        source_branch: Source branch name (None if detached HEAD)
        quiet: Whether to suppress output

    Returns:
        Path: Path to metadata file, or None on error
    """
    metadata_path = dest_path / metadata_filename

    try:
        with open(metadata_path, 'w') as f:
            f.write(f'session_id = "{session_id}"\n')
            f.write(f'manifest_version = "{MANIFEST_VERSION}"\n')
            f.write(f'baseline_commit = "{baseline_commit}"\n')
            f.write(f'original_repo_path = "{original_repo_path}"\n')

            # Write source_branch if available (not detached HEAD)
            if source_branch is not None:
                f.write(f'source_branch = "{source_branch}"\n')

            f.write('\n[subset]\n')
            f.write('paths = [\n')
            for path in subset_paths:
                f.write(f'    "{path}",\n')
            f.write(']\n')

        if not quiet:
            print(f"✓ Generated metadata file: {metadata_filename}")
            if source_branch is not None:
                print(f"  Source branch: {source_branch}")
            else:
                print(f"  Source branch: (detached HEAD)")

        return metadata_path

    except Exception as e:
        sys.stderr.write(f"Error: Failed to generate metadata file: {e}\n")
        return None


def generate_checksum(metadata_path, quiet=False):
    """
    Generate SHA256 checksum file for metadata.

    Args:
        metadata_path: Path to metadata file
        quiet: Whether to suppress output

    Returns:
        Path: Path to checksum file, or None on error
    """
    checksum_path = metadata_path.parent / f"{metadata_path.name}.sha256"

    try:
        # Read metadata file
        with open(metadata_path, 'rb') as f:
            metadata_content = f.read()

        # Calculate SHA256
        sha256_hash = hashlib.sha256(metadata_content).hexdigest()

        # Write checksum file
        with open(checksum_path, 'w') as f:
            f.write(f"{sha256_hash}\n")

        if not quiet:
            print(f"✓ Generated checksum file: {checksum_path.name}")

        return checksum_path

    except Exception as e:
        sys.stderr.write(f"Error: Failed to generate checksum file: {e}\n")
        return None


def verify_checksum(metadata_path, checksum_path, quiet=False):
    """
    Verify that the metadata file checksum matches the checksum file.

    Args:
        metadata_path: Path to metadata file
        checksum_path: Path to checksum file
        quiet: Whether to suppress output

    Returns:
        bool: True if checksum matches, False otherwise
    """
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
            sys.stderr.write(f"Error: Checksum mismatch!\n")
            sys.stderr.write(f"  Calculated: {calculated_hash}\n")
            sys.stderr.write(f"  Stored:     {stored_hash}\n")
            return False

    except Exception as e:
        sys.stderr.write(f"Error: Failed to verify checksum: {e}\n")
        return False


def set_readonly(file_path, quiet=False):
    """
    Set a file to read-only mode.

    Args:
        file_path: Path to file
        quiet: Whether to suppress output

    Returns:
        bool: True on success, False on error
    """
    try:
        current_permissions = file_path.stat().st_mode
        readonly_permissions = current_permissions & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
        os.chmod(file_path, readonly_permissions)

        if not quiet:
            print(f"✓ Set read-only: {file_path.name}")

        return True

    except Exception as e:
        sys.stderr.write(f"Error: Failed to set read-only on {file_path}: {e}\n")
        return False


def prompt_user_checksum_failure(dest_path):
    """
    Prompt user for action after checksum verification failure.

    Args:
        dest_path: Path to ephemeral repository (for cleanup if aborting)

    Returns:
        str: User choice ('abort', 'keep', or 'retry')
    """
    while True:
        sys.stderr.write("\nChecksum verification failed. What would you like to do?\n")
        sys.stderr.write("  [A]bort - Delete ephemeral repository and exit\n")
        sys.stderr.write("  [K]eep  - Keep ephemeral repository for debugging (do not sync)\n")
        sys.stderr.write("  [R]etry - Regenerate repository and metadata, then verify again\n")
        sys.stderr.write("Choice (A/K/R): ")
        sys.stderr.flush()

        choice = sys.stdin.readline().strip().lower()

        if choice in ['a', 'abort']:
            return 'abort'
        elif choice in ['k', 'keep']:
            return 'keep'
        elif choice in ['r', 'retry']:
            return 'retry'
        else:
            sys.stderr.write("Invalid choice. Please enter A, K, or R.\n")


def cleanup_ephemeral_repo(dest_path, quiet=False):
    """
    Delete the ephemeral repository directory.

    Args:
        dest_path: Path to ephemeral repository
        quiet: Whether to suppress output

    Returns:
        bool: True on success, False on error
    """
    try:
        if dest_path.exists():
            shutil.rmtree(dest_path)
            if not quiet:
                print(f"✓ Deleted ephemeral repository: {dest_path}")
        return True
    except Exception as e:
        sys.stderr.write(f"Error: Failed to delete ephemeral repository: {e}\n")
        return False


def main():
    """
    Main entry point for the creation script.
    """
    # Set up signal handler for Control-C
    signal.signal(signal.SIGINT, handle_sigint)

    # Parse arguments
    args = parse_arguments()

    # Validate arguments
    if not validate_arguments(args):
        sys.exit(1)

    # Resolve paths
    source_path = resolve_path(args.source)
    subset_path = resolve_path(args.subset)
    dest_path = resolve_path(args.destination)

    quiet = args.quiet
    dry_run = args.dry_run

    if dry_run and not quiet:
        print("=== DRY RUN MODE - No changes will be made ===\n")

    # Validate source repository
    if not validate_source_repo(source_path, quiet):
        sys.exit(1)

    # Check branch state and handle detached HEAD
    source_branch, current_commit = check_branch_state(source_path, quiet)
    if current_commit is None:
        # User aborted due to detached HEAD warning
        sys.exit(1)

    # Validate destination doesn't exist
    if not validate_destination(dest_path):
        sys.exit(1)

    # Parse subset file
    path_specs = parse_subset_file(subset_path, quiet)
    if path_specs is None:
        sys.exit(1)

    # Expand globs
    paths = expand_globs(path_specs, source_path, quiet)
    if paths is None:
        sys.exit(1)

    # Validate subset paths exist and are tracked
    if not validate_subset_paths(paths, source_path, quiet):
        sys.exit(1)

    # Check for uncommitted changes
    if not check_uncommitted_changes(paths, source_path, quiet):
        sys.exit(1)

    # Detect overlapping paths
    no_overlaps, _ = detect_overlapping_paths(paths)
    if not no_overlaps:
        sys.exit(1)

    # Get baseline commit
    baseline_commit = get_baseline_commit(source_path)
    if baseline_commit is None:
        sys.exit(1)

    if not quiet:
        print(f"✓ Baseline commit: {baseline_commit}")

    if dry_run:
        print(f"\n=== DRY RUN SUMMARY ===")
        print(f"Would create ephemeral repository at: {dest_path}")
        print(f"Would copy {len(paths)} path(s) from {source_path}")
        print(f"Baseline commit: {baseline_commit}")
        if source_branch:
            print(f"Source branch: {source_branch}")
        else:
            print(f"Source branch: (detached HEAD)")
        print(f"\nNo changes made (dry run).")
        sys.exit(0)

    # Generate session ID
    session_id = generate_session_id()
    if not quiet:
        print(f"✓ Session ID: {session_id}")

    # Main creation loop (to handle retry)
    while True:
        # Create ephemeral repository
        if not create_ephemeral_repo(dest_path, quiet):
            sys.exit(1)

        # Copy files
        if not quiet:
            print(f"\nCopying files...")
        if not copy_files_with_attributes(paths, source_path, dest_path, quiet):
            cleanup_ephemeral_repo(dest_path, quiet)
            sys.exit(1)

        # Create initial commit
        if not create_initial_commit(dest_path, quiet):
            cleanup_ephemeral_repo(dest_path, quiet)
            sys.exit(1)

        # Generate metadata
        metadata_path = generate_metadata(
            dest_path,
            args.metadata,
            session_id,
            baseline_commit,
            str(source_path),
            paths,
            source_branch,
            quiet
        )
        if metadata_path is None:
            cleanup_ephemeral_repo(dest_path, quiet)
            sys.exit(1)

        # Generate checksum
        checksum_path = generate_checksum(metadata_path, quiet)
        if checksum_path is None:
            cleanup_ephemeral_repo(dest_path, quiet)
            sys.exit(1)

        # Verify checksum
        if verify_checksum(metadata_path, checksum_path, quiet):
            # Checksum passed, break out of retry loop
            break
        else:
            # Checksum failed, prompt user
            choice = prompt_user_checksum_failure(dest_path)

            if choice == 'abort':
                cleanup_ephemeral_repo(dest_path, quiet)
                sys.stderr.write("Aborted by user.\n")
                sys.exit(1)
            elif choice == 'keep':
                sys.stderr.write(f"Ephemeral repository kept for debugging: {dest_path}\n")
                sys.stderr.write("WARNING: Do not attempt to sync this repository.\n")
                sys.exit(1)
            elif choice == 'retry':
                if not quiet:
                    print("\nRetrying: cleaning up and regenerating...\n")
                cleanup_ephemeral_repo(dest_path, quiet)
                # Loop will continue and recreate everything

    # Set metadata files to read-only
    if not set_readonly(metadata_path, quiet):
        sys.stderr.write("Warning: Failed to set metadata file to read-only\n")

    if not set_readonly(checksum_path, quiet):
        sys.stderr.write("Warning: Failed to set checksum file to read-only\n")

    # Success!
    if not quiet:
        print(f"\n{'='*60}")
        print(f"✓ Successfully created ephemeral repository!")
        print(f"{'='*60}")
        print(f"Location: {dest_path}")
        print(f"Session ID: {session_id}")
        print(f"Baseline commit: {baseline_commit}")
        if source_branch:
            print(f"Source branch: {source_branch}")
        else:
            print(f"Source branch: (detached HEAD - remember to create branch after sync!)")
        print(f"Files copied: {len(paths)} path(s)")
        print(f"\nYou can now work with the ephemeral repository.")
        print(f"When ready to sync back, run the sync script.")

    sys.exit(0)


if __name__ == '__main__':
    main()
