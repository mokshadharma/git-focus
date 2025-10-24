#!/usr/bin/env python3
"""
Test Repository Creation Script

Creates a sample repository structure with multiple files and directories
for testing the ephemeral repository creation and synchronization scripts.

Usage:
    ./create_test_repo.py <destination_directory>
    ./create_test_repo.py --help

Examples:
    ./create_test_repo.py ~/test-monorepo
    ./create_test_repo.py ./sample-repo

The script creates a git repository with:
- Multiple directories mimicking a monorepo structure
- Various file types with simple content
- Sample content that can be modified to test sync functionality
- An initial git commit

After running this script, you can:
1. Create a subset definition file listing specific paths
2. Run git-focus-create.py to create an ephemeral repository
3. Make changes in the ephemeral repository
4. Run git-focus-sync.py to sync changes back
"""

import sys
import os
import subprocess
from pathlib import Path


def print_help():
    """
    Print detailed help information to stderr.
    """
    help_text = """
Test Repository Creation Script

Creates a sample repository structure for testing ephemeral repository
creation and synchronization.

Usage:
    ./create_test_repo.py <destination_directory>

Arguments:
    destination_directory    Path where the test repository will be created

Example:
    ./create_test_repo.py ~/test-monorepo

The created repository will contain:
- src/api/         - API handler files
- src/models/      - Data model files
- src/utils/       - Utility functions
- src/frontend/    - Frontend code
- tests/           - Test files
- docs/            - Documentation
- config/          - Configuration files
- scripts/         - Utility scripts

After creation, the directory will be initialized as a git repository
with all files committed.
"""
    sys.stderr.write(help_text)


def create_directory_structure(base_path):
    """
    Create the directory structure for the test repository.

    Args:
        base_path: Base path for the repository

    Returns:
        bool: True on success, False on error
    """
    directories = [
        'src/api/handlers',
        'src/api/middleware',
        'src/models',
        'src/utils',
        'src/frontend/components',
        'src/frontend/styles',
        'tests/api',
        'tests/models',
        'tests/integration',
        'docs/api',
        'docs/guides',
        'config',
        'scripts',
        'data/samples',
    ]

    try:
        for dir_path in directories:
            full_path = base_path / dir_path
            full_path.mkdir(parents=True, exist_ok=True)

        print(f"✓ Created directory structure")
        return True

    except Exception as e:
        sys.stderr.write(f"Error: Failed to create directory structure: {e}\n")
        return False


def create_file(file_path, content):
    """
    Create a file with the given content.

    Args:
        file_path: Path to the file
        content: Content to write to the file

    Returns:
        bool: True on success, False on error
    """
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w') as f:
            f.write(content)
        return True
    except Exception as e:
        sys.stderr.write(f"Error: Failed to create file {file_path}: {e}\n")
        return False


def create_sample_files(base_path):
    """
    Create sample files with simple content.

    Args:
        base_path: Base path for the repository

    Returns:
        bool: True on success, False on error
    """
    files = {
        'README.md': """# Test Monorepo

This is a sample monorepo for testing.

Line 3
Line 4
Line 5
""",

        'src/api/handlers/user.py': """# User handler
alpha
beta
gamma
delta
epsilon
""",

        'src/api/handlers/auth.py': """# Auth handler
auth_alpha
auth_beta
auth_gamma
auth_delta
auth_epsilon
""",

        'src/api/middleware/logging.py': """# Logging middleware
log_one
log_two
log_three
log_four
log_five
""",

        'src/models/user.py': """# User model
model_a
model_b
model_c
model_d
model_e
""",

        'src/utils/validation.py': """# Validation utilities
validate_1
validate_2
validate_3
validate_4
validate_5
""",

        'src/frontend/components/UserList.js': """// User list component
component_alpha
component_beta
component_gamma
component_delta
component_epsilon
""",

        'src/frontend/styles/main.css': """/* Main styles */
style_one
style_two
style_three
style_four
style_five
""",

        'tests/api/test_user.py': """# User tests
test_alpha
test_beta
test_gamma
test_delta
test_epsilon
""",

        'tests/models/test_user_model.py': """# User model tests
model_test_1
model_test_2
model_test_3
model_test_4
model_test_5
""",

        'docs/api/authentication.md': """# Authentication API

Section 1
Section 2
Section 3
Section 4
Section 5
""",

        'docs/guides/getting_started.md': """# Getting Started

Step 1
Step 2
Step 3
Step 4
Step 5
""",

        'config/database.yaml': """# Database config
db_line_1
db_line_2
db_line_3
db_line_4
db_line_5
""",

        'config/app.yaml': """# App config
app_line_1
app_line_2
app_line_3
app_line_4
app_line_5
""",

        'scripts/init_db.py': """#!/usr/bin/env python3
# Database init
init_1
init_2
init_3
init_4
init_5
""",

        'scripts/migrate.py': """#!/usr/bin/env python3
# Migration script
migrate_1
migrate_2
migrate_3
migrate_4
migrate_5
""",

        '.gitignore': """# Python
__pycache__/
*.pyc
*.db

# OS
.DS_Store
""",

        'data/samples/users.json': """[
  {"id": 1, "name": "alice"},
  {"id": 2, "name": "bob"},
  {"id": 3, "name": "charlie"}
]
""",
    }

    file_count = 0
    for rel_path, content in files.items():
        file_path = base_path / rel_path
        if create_file(file_path, content):
            file_count += 1
        else:
            return False

    print(f"✓ Created {file_count} sample files")
    return True


def initialize_git_repo(base_path):
    """
    Initialize a git repository and create initial commit.

    Args:
        base_path: Path to repository

    Returns:
        bool: True on success, False on error
    """
    try:
        # Initialize git repository
        subprocess.run(
            ['git', 'init'],
            cwd=base_path,
            capture_output=True,
            check=True
        )
        print(f"✓ Initialized git repository")

        # Configure git user (for the initial commit)
        subprocess.run(
            ['git', 'config', 'user.name', 'Test User'],
            cwd=base_path,
            capture_output=True,
            check=True
        )
        subprocess.run(
            ['git', 'config', 'user.email', 'test@example.com'],
            cwd=base_path,
            capture_output=True,
            check=True
        )

        # Add all files
        subprocess.run(
            ['git', 'add', '.'],
            cwd=base_path,
            capture_output=True,
            check=True
        )
        print(f"✓ Added all files to git")

        # Create initial commit
        subprocess.run(
            ['git', 'commit', '-m', 'Initial commit: Test repository structure'],
            cwd=base_path,
            capture_output=True,
            check=True
        )
        print(f"✓ Created initial commit")

        # Get commit hash
        result = subprocess.run(
            ['git', 'rev-parse', 'HEAD'],
            cwd=base_path,
            capture_output=True,
            text=True,
            check=True
        )
        commit_hash = result.stdout.strip()
        print(f"✓ Initial commit hash: {commit_hash}")

        return True

    except subprocess.CalledProcessError as e:
        sys.stderr.write(f"Error: Failed to initialize git repository: {e}\n")
        if e.stderr:
            sys.stderr.write(f"{e.stderr.decode()}\n")
        return False


def create_example_subset_file(base_path):
    """
    Create an example subset definition file.

    Args:
        base_path: Path to repository

    Returns:
        bool: True on success, False on error
    """
    subset_content = """# Example subset definition for testing
# This file can be used with git-focus-create.py

# API handlers
src/api/handlers/user.py
src/api/handlers/auth.py

# User model
src/models/user.py

# Tests
tests/api/test_user.py

# Documentation
docs/api/authentication.md
"""

    subset_path = base_path / 'example_subset.txt'

    if create_file(subset_path, subset_content):
        print(f"✓ Created example subset file: example_subset.txt")
        return True

    return False


def main():
    """
    Main entry point for the test repository creation script.
    """
    # Check arguments
    if len(sys.argv) < 2:
        sys.stderr.write("Error: Missing required argument\n")
        print_usage()
        sys.exit(1)

    if sys.argv[1] in ['--help', '-h']:
        print_help()
        sys.exit(0)

    # Get destination path
    dest_path = Path(sys.argv[1]).resolve()

    # Check if destination already exists
    if dest_path.exists():
        sys.stderr.write(f"Error: Destination directory already exists: {dest_path}\n")
        sys.exit(1)

    print(f"Creating test repository: {dest_path}")
    print()

    # Create destination directory
    try:
        dest_path.mkdir(parents=True, exist_ok=False)
        print(f"✓ Created base directory: {dest_path}")
    except Exception as e:
        sys.stderr.write(f"Error: Failed to create destination directory: {e}\n")
        sys.exit(1)

    # Create directory structure
    if not create_directory_structure(dest_path):
        sys.exit(1)

    # Create sample files
    if not create_sample_files(dest_path):
        sys.exit(1)

    # Initialize git repository
    if not initialize_git_repo(dest_path):
        sys.exit(1)

    # Create example subset file
    if not create_example_subset_file(dest_path):
        sys.exit(1)

    # Success!
    print()
    print(f"{'='*60}")
    print(f"✓ Successfully created test repository!")
    print(f"{'='*60}")
    print(f"Location: {dest_path}")
    print()
    print("Next steps:")
    print("1. cd", dest_path)
    print("2. Review the example_subset.txt file")
    print("3. Run git-focus-create.py with the subset file")
    print("4. Make changes in the ephemeral repository")
    print("5. Run git-focus-sync.py to sync back")
    print()
    print("Example commands:")
    print(f"  cd {dest_path}")
    print(f"  ../git-focus-create.py --source . --subset example_subset.txt --destination ../ephemeral-test")

    sys.exit(0)


def print_usage():
    """Print brief usage information."""
    sys.stderr.write("Usage: create_test_repo.py <destination_directory>\n")
    sys.stderr.write("       create_test_repo.py --help\n")


if __name__ == '__main__':
    main()
