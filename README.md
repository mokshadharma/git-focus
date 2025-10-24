# git-focus

Ephemeral Repository Scripts for LLM-Powered Development

These scripts provide a workflow to create a temporary, isolated "ephemeral" repository from a large monorepo. This allows a Large Language Model (LLM) to work on a specific subset of files without being confused by the surrounding code, and then safely synchronize the changes back.

---

## The Problem: LLMs and Large Repositories

Using Large Language Models (LLMs) for code generation in large-scale monorepos presents significant challenges:

1.  **Context Window Overload:** LLMs have a finite context window. When faced with a repository containing thousands of files, the vast majority of that code is irrelevant to the task at hand. This irrelevant code floods the context, leaving little room for the files the LLM actually needs to read and modify.
2.  **Model Confusion:** The presence of so much unrelated code can confuse the LLM. It may draw patterns, import statements, or function calls from incorrect parts of the repository, leading to buggy or out-of-place code that fails to respect the local conventions of the target module.

This makes it nearly impossible for an LLM to perform complex, multi-file tasks effectively in a typical monorepo environment.

## The Solution: A Focused, Two-Step Workflow

These scripts solve the problem by creating a temporary, clean, and focused environment for the LLM to work in, and then integrating the results back into the main repository.

1.  **`git-focus-create.py` (The Context Filter):** This script carves out a small, isolated workspace containing *only* the files and directories relevant to the task. It generates a new, lightweight Git repository, providing the LLM with a sterile environment free from the noise of the larger monorepo.

2.  **`git-focus-sync.py` (The Integration Layer):** After the LLM has completed its work in the ephemeral repository, this script safely transfers the new, LLM-generated commits back into the original monorepo. It preserves commit history, messages, and authors while handling the complexities of integration.

This workflow enables the LLM to operate at peak efficiency, as if it were working in a small, purpose-built repository.

## Usage and Workflow

Here is the step-by-step process for using the scripts.

### Prerequisites

*   Python 3.x
*   A `subset.txt` file defining the files and directories to include.

The `subset.txt` file is a simple text file where each line is a path relative to the root of the monorepo. It supports glob patterns.

**Example `subset.txt`:**
```
# Include the main application directory
src/app/

# Include a specific utility file
src/utils/data_processing.py

# Include all test files for the app
tests/app/**/*.py

# Include project configuration
package.json
```

### Step 1: Create the Ephemeral Repository

First, use `git-focus-create.py` to generate the isolated repository for the LLM.

**Command:**
```bash
./git-focus-create.py --source /path/to/monorepo --subset /path/to/subset.txt --destination /path/to/new_ephemeral_repo
```

**Arguments:**
*   `--source`: The path to the original, large monorepo.
*   `--subset`: The path to the file defining the subset of files to include.
*   `--destination`: The directory where the new ephemeral repository will be created.

This command performs several safety checks (e.g., for uncommitted changes) and then creates the new repository at the destination path. It will contain an initial commit representing the "baseline" state and a `metadata` file required for the sync process.

### Step 2: Let the LLM Work

Point your LLM-based development agent to the newly created ephemeral repository. The LLM can now read, modify, and commit changes within this clean environment.

Because the repository is small and focused, the LLM can use its full context window to understand the relevant code, leading to better and more accurate results.

### Step 3: Synchronize the Changes Back

Once the LLM has finished its work and created one or more commits, use `git-focus-sync.py` to merge the changes back into the original monorepo.

**Navigate to the ephemeral repository directory** and run the script.

**Command:**
```bash
cd /path/to/new_ephemeral_repo
./git-focus-sync.py
```
*(Note: The script is designed to be run from within the ephemeral repository, but you can also specify its location with `--destination`)*.

This script will:
1.  Read the `metadata` file to find the original repository and baseline commit.
2.  Perform extensive safety checks to prevent data loss or incorrect merges.
3.  Identify all new commits made by the LLM.
4.  Create a temporary branch in the original monorepo.
5.  Replay each new commit onto the temporary branch, preserving the author, message, and timestamp.
6.  If successful, merge the temporary branch into your original working branch and clean up.

If any step fails, the script will abort safely and provide instructions for manual cleanup, ensuring your original repository is never left in a broken state.

### Dry Run Mode

Both scripts support a `--dry-run` flag, which allows you to preview the actions that would be taken without making any actual changes to the filesystem. This is highly recommended to ensure your configuration is correct.

**Example:**
```bash
# Preview the creation process
./git-focus-create.py --source ... --subset ... --destination ... --dry-run

# Preview the synchronization process
./git-focus-sync.py --dry-run
```
