"""
GitUtils.py - Utilities for Git operations

This module contains functions for interacting with Git repositories,
including committing changes, pulling updates, and retrieving commit information.
"""

import os
import subprocess
import logging
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama for cross-platform color support
init(autoreset=True)

# Import from the same package
from .Parameters import Config

##########################################################################
# Git Operations
##########################################################################

def display_git_changes(status_output):
    """
    Display a categorized list of Git changes with colored output.
    
    Args:
        status_output (str): Output from 'git status --porcelain'
    
    Returns:
        dict: Dictionary with counts of modified, added, and deleted files
    """
    if not status_output.strip():
        return {'modified': 0, 'added': 0, 'deleted': 0}
    
    modified_files = []
    added_files = []
    deleted_files = []
    
    # Parse git status --porcelain output
    for line in status_output.strip().split('\n'):
        if not line:
            continue
            
        # First two characters indicate status
        status = line[:2]
        # Skip the 2-character status code and strip any leading whitespace
        filename = line[2:].lstrip()
        
        # M = modified, A = added, D = deleted, ?? = untracked (new)
        if 'M' in status:
            modified_files.append(filename)
        elif 'A' in status or '??' in status:
            added_files.append(filename)
        elif 'D' in status:
            deleted_files.append(filename)
        elif 'R' in status:  # Renamed files
            modified_files.append(filename)
    
    # Display changes with colors
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Git Changes Summary")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    total_changes = len(modified_files) + len(added_files) + len(deleted_files)
    
    if added_files:
        print(f"\n{Fore.GREEN}✓ Added ({len(added_files)} files):{Style.RESET_ALL}")
        for file in added_files:
            print(f"  {Fore.GREEN}+ {file}{Style.RESET_ALL}")
    
    if modified_files:
        print(f"\n{Fore.YELLOW}⚡ Modified ({len(modified_files)} files):{Style.RESET_ALL}")
        for file in modified_files:
            print(f"  {Fore.YELLOW}~ {file}{Style.RESET_ALL}")
    
    if deleted_files:
        print(f"\n{Fore.RED}✗ Deleted ({len(deleted_files)} files):{Style.RESET_ALL}")
        for file in deleted_files:
            print(f"  {Fore.RED}- {file}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Total: {total_changes} file(s) will be committed")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    logging.info(f"Changes detected: {len(added_files)} added, {len(modified_files)} modified, {len(deleted_files)} deleted")
    
    return {
        'modified': len(modified_files),
        'added': len(added_files),
        'deleted': len(deleted_files)
    }

def commit_changes_to_git(changes_description="Exported Azure Firewall policies to Bicep", with_push=True):
    """
    Commit and push changes to Git repository.
    
    This function performs the following Git operations:
    1. Adds all changes to the staging area
    2. Creates a commit with the provided description
    3. Pushes the changes to the remote repository
    
    Args:
        changes_description (str): Description of the changes made
        with_push (bool): Whether to push changes to remote repository
    
    Returns:
        bool: True if commit was successful, False otherwise
    """
    
    logging.info("Starting Git operations to commit and push changes...")
    
    try:
        # Verify Git is properly configured before proceeding
        try:
            # Check if we're in a Git repository
            git_dir_result = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], 
                                          shell=Config.USE_SHELL_IN_SUBPROCESS,
                                          capture_output=True, 
                                          text=True, 
                                          check=False)
            
            if git_dir_result.returncode != 0:
                logging.error("Not in a Git repository or Git is not installed")
                if git_dir_result.stderr:
                    logging.error(f"Git error: {git_dir_result.stderr}")
                return False
                
            # Check if user.name and user.email are configured
            git_config_result = subprocess.run(["git", "config", "--list"], 
                                             shell=Config.USE_SHELL_IN_SUBPROCESS,
                                             capture_output=True, 
                                             text=True, 
                                             check=False)
            
            git_config = git_config_result.stdout
            if "user.name" not in git_config or "user.email" not in git_config:
                logging.warning("Git user.name or user.email not configured. Commit may fail.")
                
            # Check for any unstaged changes
            git_status_result = subprocess.run(["git", "status", "--porcelain"], 
                                             shell=Config.USE_SHELL_IN_SUBPROCESS,
                                             capture_output=True, 
                                             text=True, 
                                             check=False)
            
            if not git_status_result.stdout.strip():
                logging.info("No changes detected in the working directory")
                return True
            
            # Display changes before committing
            display_git_changes(git_status_result.stdout)
            
        except Exception as e:
            logging.warning(f"Error checking Git configuration: {str(e)}")
            # Continue with the commit process anyway
        
        # Use the provided commit message as is
        commit_message = changes_description
        
        # Git add all changes
        logging.info("Adding changes to Git staging area...")
        add_result = subprocess.run(["git", "add", "*"], 
                                    shell=Config.USE_SHELL_IN_SUBPROCESS,
                                    capture_output=True, 
                                    text=True, 
                                    check=False)
        
        if add_result.returncode != 0:
            logging.error(f"Failed to add files to Git with return code {add_result.returncode}")
            if add_result.stdout:
                logging.error(f"Git add stdout: {add_result.stdout}")
            if add_result.stderr:
                logging.error(f"Git add stderr: {add_result.stderr}")
            logging.error("Git command: git add *")
            return False
        
        # Git commit with timestamp and description
        logging.info(f"Committing changes with message: {commit_message}")
        commit_result = subprocess.run(["git", "commit", "-m", commit_message], 
                                       shell=Config.USE_SHELL_IN_SUBPROCESS,
                                       capture_output=True, 
                                       text=True, 
                                       check=False)
        
        if commit_result.returncode != 0:
            # Check if there's nothing to commit
            if "nothing to commit" in commit_result.stdout or "nothing to commit" in commit_result.stderr:
                logging.info("No changes to commit")
                return True
            else:
                # Log more detailed error information
                logging.error(f"Failed to commit changes with return code {commit_result.returncode}")
                if commit_result.stdout:
                    logging.error(f"Commit stdout: {commit_result.stdout}")
                if commit_result.stderr:
                    logging.error(f"Commit stderr: {commit_result.stderr}")
                # Log the git command that was run
                logging.error(f"Git command: git commit -m \"{commit_message}\"")
                return False
        
        # Git push if requested
        if with_push:
            logging.info("Pushing changes to remote repository...")
            
            # Get current branch name
            branch_result = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"],
                                         shell=Config.USE_SHELL_IN_SUBPROCESS,
                                         capture_output=True,
                                         text=True,
                                         check=False)
            
            if branch_result.returncode == 0:
                current_branch = branch_result.stdout.strip()
                logging.info(f"Pushing to branch: {current_branch}")
                
                # Push with --set-upstream to establish tracking
                push_result = subprocess.run(["git", "push", "--set-upstream", "origin", current_branch], 
                                            shell=Config.USE_SHELL_IN_SUBPROCESS,
                                            capture_output=True, 
                                            text=True, 
                                            check=False)
            else:
                # Fallback to simple push if we can't get branch name
                logging.warning("Could not determine current branch, using simple push")
                push_result = subprocess.run(["git", "push"], 
                                            shell=Config.USE_SHELL_IN_SUBPROCESS,
                                            capture_output=True, 
                                            text=True, 
                                            check=False)
            
            if push_result.returncode != 0:
                logging.error(f"Failed to push changes: {push_result.stderr}")
                return False
        
        logging.info(f"Successfully committed changes to Git repository")
        return True
        
    except Exception as e:
        logging.error(f"Error during Git operations: {str(e)}", exc_info=True)
        return False
    
def pull_changes_from_git(branch_name=None):
    """
    Pull the latest changes from the remote Git repository to the local branch.
    
    This function performs the following Git operations:
    1. Fetches the latest changes from the remote repository
    2. Pulls changes into the current or specified branch
    
    Args:
        branch_name (str, optional): The name of the branch to pull. If None, uses the current branch.
    
    Returns:
        bool: True if all Git operations were successful, False otherwise
    """
    
    logging.info("Starting Git operations to pull latest changes...")
    
    try:
        # Fetch latest changes from remote and prune stale remote-tracking branches
        logging.info("Fetching latest changes from remote repository and pruning stale branches...")
        fetch_result = subprocess.run(["git", "fetch", "--prune"], 
                                      shell=Config.USE_SHELL_IN_SUBPROCESS,
                                      capture_output=True, 
                                      text=True, 
                                      check=False)
        
        if fetch_result.returncode != 0:
            logging.error(f"Failed to fetch from remote: {fetch_result.stderr}")
            return False
        
        # Prepare pull command
        pull_cmd = ["git", "pull"]
        if branch_name:
            # If branch name is specified, add origin and branch name
            current_branch = branch_name
            pull_cmd.extend(["origin", branch_name])
            logging.info(f"Pulling changes into branch: {branch_name}")
        else:
            # Get current branch name
            branch_result = subprocess.run(["git", "branch", "--show-current"], 
                                          shell=Config.USE_SHELL_IN_SUBPROCESS,
                                          capture_output=True, 
                                          text=True, 
                                          check=False)
            if branch_result.returncode != 0:
                logging.error(f"Failed to get current branch: {branch_result.stderr}")
                return False
            
            current_branch = branch_result.stdout.strip()
            logging.info(f"Pulling changes into current branch: {current_branch}")
        
        # Pull changes from remote
        pull_result = subprocess.run(pull_cmd, 
                                     shell=Config.USE_SHELL_IN_SUBPROCESS,
                                     capture_output=True, 
                                     text=True, 
                                     check=False)
        
        if pull_result.returncode != 0:
            logging.error(f"Failed to pull changes: {pull_result.stderr}")
            return False
        
        # Check if there were changes
        if "Already up to date" in pull_result.stdout:
            logging.info("Local branch is already up to date")
        else:
            logging.info(f"Successfully pulled latest changes into {current_branch}")
        
        return True
        
    except Exception as e:
        logging.error(f"Error during Git pull operations: {str(e)}", exc_info=True)
        return False

def get_git_commit_id():
    """
    Get the latest Git commit ID (short hash).
    
    This function retrieves the short hash of the latest commit in the current branch
    using the 'git log -1 --format=%h' command.
    
    Returns:
        str: Short hash of the latest commit (e.g., '3f7a9e1'), or None if an error occurs
    """
    
    logging.info("Retrieving latest Git commit ID...")
    
    try:
        # Get the short hash of the latest commit
        cmd = ["git", "log", "-1", "--format=%h"]
        result = subprocess.run(cmd, 
                               shell=Config.USE_SHELL_IN_SUBPROCESS,
                               capture_output=True, 
                               text=True, 
                               check=True)
        
        # Extract and clean the commit ID
        commit_id = result.stdout.strip()
        
        if commit_id:
            logging.info(f"Retrieved Git commit ID: {commit_id}")
            return commit_id
        else:
            logging.warning("Failed to retrieve Git commit ID: empty result")
            return None
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to retrieve Git commit ID: {e.stderr}")
        return None
    except Exception as e:
        logging.error(f"Error retrieving Git commit ID: {str(e)}", exc_info=True)
        return None

def get_current_branch():
    """
    Get the name of the current Git branch.
    
    Returns:
        str: Current branch name, or None if unable to determine
    """
    try:
        result = subprocess.run(
            ['git', 'branch', '--show-current'],
            shell=Config.USE_SHELL_IN_SUBPROCESS,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except Exception as e:
        logging.error(f"Error getting current branch: {str(e)}")
        return None

def get_available_branches():
    """
    Get list of available Git branches (both local and remote).
    
    Returns:
        dict: Dictionary with 'local' and 'remote' branch lists
            {
                'local': ['main', 'feature1', ...],
                'remote': ['origin/main', 'origin/feature2', ...]
            }
            Returns None if unable to get branches
    """
    try:
        # Fetch updates from remote first
        fetch_result = subprocess.run(
            ['git', 'fetch', '--all', '--prune'],
            shell=Config.USE_SHELL_IN_SUBPROCESS,
            capture_output=True,
            text=True,
            check=False
        )
        
        if fetch_result.returncode != 0:
            logging.warning(f"Failed to fetch from remote: {fetch_result.stderr}")
        
        # Get local branches
        local_result = subprocess.run(
            ['git', 'branch', '--format=%(refname:short)'],
            shell=Config.USE_SHELL_IN_SUBPROCESS,
            capture_output=True,
            text=True,
            check=True
        )
        local_branches = [b.strip() for b in local_result.stdout.splitlines() if b.strip()]
        
        # Get remote branches
        remote_result = subprocess.run(
            ['git', 'branch', '-r', '--format=%(refname:short)'],
            shell=Config.USE_SHELL_IN_SUBPROCESS,
            capture_output=True,
            text=True,
            check=True
        )
        remote_branches = [
            b.strip() for b in remote_result.stdout.splitlines() 
            if b.strip() and 'HEAD' not in b
        ]
        
        return {
            'local': local_branches,
            'remote': remote_branches
        }
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to get Git branches: {e.stderr}")
        return None
    except Exception as e:
        logging.error(f"Error getting Git branches: {str(e)}")
        return None

def switch_git_branch(branch_name):
    """
    Switch to the specified Git branch.
    
    Args:
        branch_name: Name of the branch to switch to
        
    Returns:
        tuple: (success: bool, branch_name: str)
            - success: True if branch switch was successful
            - branch_name: Name of the branch switched to (or None if failed)
    """
    try:
        # Validate branch name is provided
        if not branch_name:
            logging.error("Branch name is required")
            return False, None
        
        # Get current branch
        current_branch = get_current_branch()
        if current_branch == branch_name:
            logging.info(f"Already on branch: {branch_name}")
            return True, branch_name
        
        # Check if branch exists locally
        result = subprocess.run(
            ['git', 'branch', '--list', branch_name],
            shell=Config.USE_SHELL_IN_SUBPROCESS,
            capture_output=True,
            text=True,
            check=False
        )
        
        branch_exists_locally = bool(result.stdout.strip())
        
        # Switch to the branch
        if branch_exists_locally:
            # Switch to existing local branch
            logging.info(f"Switching to existing local branch: {branch_name}")
            result = subprocess.run(
                ['git', 'checkout', branch_name],
                shell=Config.USE_SHELL_IN_SUBPROCESS,
                capture_output=True,
                text=True,
                check=True
            )
        else:
            # Check if branch exists on remote
            result = subprocess.run(
                ['git', 'branch', '-r', '--list', f'origin/{branch_name}'],
                shell=Config.USE_SHELL_IN_SUBPROCESS,
                capture_output=True,
                text=True,
                check=False
            )
            
            branch_exists_remotely = bool(result.stdout.strip())
            
            if branch_exists_remotely:
                # Create local branch tracking remote
                logging.info(f"Creating local branch tracking remote: origin/{branch_name}")
                result = subprocess.run(
                    ['git', 'checkout', '-b', branch_name, f'origin/{branch_name}'],
                    shell=Config.USE_SHELL_IN_SUBPROCESS,
                    capture_output=True,
                    text=True,
                    check=True
                )
            else:
                # Branch doesn't exist
                logging.error(f"Branch '{branch_name}' does not exist locally or remotely")
                return False, None
        
        logging.info(f"Successfully switched to branch: {branch_name}")
        return True, branch_name
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Git command failed: {e.stderr}")
        return False, None
    except Exception as e:
        logging.error(f"Error switching branch: {str(e)}")
        return False, None

def checkout_branch(branch_name):
    """
    Checkout to a specific Git branch.
    
    Helper function for switch_git_branch that handles the actual checkout operation.
    
    Args:
        branch_name (str): Name of the branch to checkout
    
    Returns:
        bool: True if checkout was successful, False otherwise
        str: Name of the checked out branch or None if checkout failed
    """
    logging.info(f"Attempting to checkout branch: {branch_name}")
    
    try:
        # Check if it's a remote branch
        is_remote = branch_name.startswith('origin/')
        
        if is_remote:
            # For remote branches, we need to create a local tracking branch
            local_branch = branch_name.split('/', 1)[1]
            
            # Check if local branch with same name exists
            branch_exists_cmd = ["git", "show-ref", "--verify", f"refs/heads/{local_branch}"]
            branch_exists_result = subprocess.run(
                branch_exists_cmd,
                shell=Config.USE_SHELL_IN_SUBPROCESS,
                capture_output=True,
                check=False
            )
            
            if branch_exists_result.returncode == 0:
                # Branch exists, just check it out and update
                checkout_cmd = ["git", "checkout", local_branch]
                logging.info(f"Local branch {local_branch} already exists, checking out and updating...")
            else:
                # Branch doesn't exist, create tracking branch
                checkout_cmd = ["git", "checkout", "-b", local_branch, branch_name]
                logging.info(f"Creating new local branch {local_branch} tracking {branch_name}...")
        else:
            # For local branches, just check them out
            checkout_cmd = ["git", "checkout", branch_name]
            local_branch = branch_name
            
        checkout_result = subprocess.run(
            checkout_cmd,
            shell=Config.USE_SHELL_IN_SUBPROCESS,
            capture_output=True,
            text=True,
            check=False
        )
        
        if checkout_result.returncode != 0:
            logging.error(f"Failed to checkout branch: {checkout_result.stderr}")
            print(f"Failed to checkout branch: {checkout_result.stderr}")
            return False, None
            
        # If it was a remote branch, pull the latest changes
        if is_remote:
            pull_cmd = ["git", "pull"]
            pull_result = subprocess.run(
                pull_cmd,
                shell=Config.USE_SHELL_IN_SUBPROCESS,
                capture_output=True,
                text=True,
                check=False
            )
            
            if pull_result.returncode != 0:
                logging.warning(f"Checked out branch {local_branch} but failed to pull latest changes: {pull_result.stderr}")
                print(f"Warning: Checked out branch but failed to pull latest changes.")
            
        logging.info(f"Successfully checked out branch: {local_branch}")
        print(f"Successfully checked out branch: {Fore.GREEN}{local_branch}{Style.RESET_ALL}")
        return True, local_branch
        
    except Exception as e:
        logging.error(f"Error during branch checkout: {str(e)}", exc_info=True)
        return False, None
