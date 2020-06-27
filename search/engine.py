"""
Search through Git diffs for secrets
"""
from git import Repo, NULL_TREE
import git
import hashlib
from typing import Dict, List, Any
import tempfile
import datetime
import math
import re
import json
from interface.colors import bcolors
import uncompyle6
import io


BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"


class SearchEngine():

    __slots__ = ['repo', 'regexes', 'since_commit', 'findings', 'path_inclusions', 'path_exclusions', 'max_depth', 'already_searched']

    def __init__(self, repo: Repo, regexes: Dict[str, str], path_inclusions: str, path_exclusions: str, since_commit: str=None, max_depth: int=math.inf):
        self.repo = repo                                                    # The repo to search
        self.regexes = regexes                                              # The regex searches to perform on the repo       
        self.findings = []                                                  # The findings (secrets) that the engine discovers
        self.path_inclusions = self._compile_path_regexes(path_inclusions)  # Iterable of compiled regex searches for paths to include in the search
        self.path_exclusions = self._compile_path_regexes(path_exclusions)  # Iterable of compiled regex searches for paths to exclude from the search
        self.since_commit = since_commit                                    # Hash of the commit to search forward from
        self.max_depth = max_depth                                          # Maximum depth of commit to search
        self.already_searched = set()                                       # These are the hashes of diffs that have already been searched

    def find_secrets(self, branch: str=None, print_json: bool=False) -> List:
        """
        Search through a git repo for secrets

        :param repo: GitPython Repo object that contains the repo to search through
        :param branch:
        :param max_depth:
        :param since_commit:
        """     
        # If the user specified a branch, then go down that one, otherwise go down all branches
        if branch:
            branches = self.repo.remotes.origin.fetch(branch)
        else:
            branches = self.repo.remotes.origin.fetch()

        # For each branch that the user specified
        for remote_branch in branches:
            self._search_branch(remote_branch)

        # Print the results
        self._print_results(print_json)

    def _print_results(self, print_json: bool=False) -> None:
        """
        Print the findings 
        """
        if print_json:
            for finding in self.findings:
                print(json.dumps(finding))
        else:
            print("FINDINGS\n#########################################")
            for finding in self.findings:
                for key, value in finding.items():
                    if key != "diff":
                        print(f"{key:15}=> {value}")
                    else:
                        print(f"{key}\n--------\n{value}")
                print("\n#########################################\n")


    @staticmethod
    def _calculate_diff_hash(prev_commit: str, curr_commit: str) -> str:
        """
        Calculate the hash of a diff between two commits
        """
        return hashlib.md5((str(prev_commit) + str(curr_commit)).encode('utf-8')).digest()

    @staticmethod
    def _compile_path_regexes(filename: str) -> List[Any]: # TODO validate that this functionality works
        """
        Compile the user specified file paths into regex expressions
        """
        # If the user didn't specifiy any paths
        if filename is None:
            return None
        # For each line in the file, compile the regex
        paths = []
        with open(filename, "r") as f:
            for pattern in set(l[:-1].lstrip() for l in f):
                if pattern and not pattern.startswith('#'):
                    paths.append(re.compile(pattern))
        return paths

    def _path_included(self, blob) -> bool:
        """Check if the diff blob object should included in analysis.

        If defined and non-empty, `include_patterns` has precedence over `exclude_patterns`, such that a blob that is not
        matched by any of the defined `include_patterns` will be excluded, even when it is not matched by any of the defined
        `exclude_patterns`. If either `include_patterns` or `exclude_patterns` are undefined or empty, they will have no
        effect, respectively. All blobs are included by this function when called with default arguments.

        :param blob: a Git diff blob object
        :param include_patterns: iterable of compiled regular expression objects; when non-empty, at least one pattern must
        match the blob object for it to be included; if empty or None, all blobs are included, unless excluded via
        `exclude_patterns`
        :param exclude_patterns: iterable of compiled regular expression objects; when non-empty, _none_ of the patterns may
        match the blob object for it to be included; if empty or None, no blobs are excluded if not otherwise
        excluded via `include_patterns`
        :return: False if the blob is _not_ matched by `include_patterns` (when provided) or if it is matched by
        `exclude_patterns` (when provided), otherwise returns True 
        """
        path = blob.b_path if blob.b_path else blob.a_path
        if self.path_inclusions and not any(p.match(path) for p in self.path_inclusions):
            return False
        if self.path_exclusions and any(p.match(path) for p in self.path_exclusions):
            return False
        return True

    def _search_branch(self, branch: git.remote.FetchInfo) -> None:
        """
        Search through a specific git branch for secrets. This function will start at the most recent commit, and then
        compare itself (diff) to the previous commit on the branch. If it discovers that a specific diff has already been
        searched then it will skip it
        """
        prev_commit = None
        for curr_commit in self.repo.iter_commits(branch.name, max_count=self.max_depth):

            # Check to see if the last commit that user specified has been reached
            # If it has then end the search on this branch
            if curr_commit.hexsha == self.since_commit and self.since_commit != None:
                return

            # get the hash of this diff
            diff_hash = self._calculate_diff_hash(prev_commit, curr_commit)

            # If there is no previous commit, then this is the newest (most recent) commit, so we have nothing to diff with.
            # If this diff has already been searched by the application, then skip it.
            # Otherwise, This diff has not been searched yet
            if prev_commit and diff_hash not in self.already_searched:
                # Get the actual diff contents
                diff = prev_commit.diff(curr_commit, create_patch=True)

                # Add the diff hash to the searched list
                self.already_searched.add(diff_hash)

                # Search through the diff for secrets
                self._search_diff(diff, curr_commit, prev_commit, branch.name)

            # Set the current commit as the previous (newer) commit    
            prev_commit = curr_commit

        # Handling the first commit, diff the first commit with NULL_TREE here to check the oldest code.
        diff = curr_commit.diff(NULL_TREE, create_patch=True)
        self._search_diff(diff, curr_commit, prev_commit, branch.name)

    def _search_diff(self, diff, curr_commit, prev_commit, branch_name):
        """
        Look through a git diff for secrets
        """
        # for each specific change within the overall diff
        for blob in diff:

            # PyCache integration, check if the blob is a pycache file. If it is then decompyle ;)
            path = blob.b_path if blob.b_path else blob.a_path
            if path.endswith(".pyc"):
                with tempfile.NamedTemporaryFile(suffix=".pyc") as f:
                    # Write the contents of the diffed pycache file to a tempfile 
                    f.write(blob.b_blob.data_stream.read())
                    f.seek(0)

                    # uncompyle it
                    printable_diff = io.StringIO()
                    uncompyle6.decompile_file(f.name, printable_diff)
                    printable_diff.seek(0)
                    printable_diff = printable_diff.read()

            # Get the individual blob (source code) as utf-8 text
            else:    
                printable_diff = blob.diff.decode('utf-8', errors='replace')

                # Ignore binary files, this is what the blob decode function will return if the blob is binary and
                # check to see if the blob is in a file that should be exculded
                if printable_diff.startswith("Binary files") and not self._path_included(blob):
                    continue

            # Find the secrets within the diff
            commit_time = datetime.datetime.fromtimestamp(prev_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
            self._find_entropy(printable_diff, commit_time, branch_name, prev_commit, blob, curr_commit.hexsha)
            self._regex_check(printable_diff, commit_time, branch_name, prev_commit, blob, curr_commit.hexsha)

    @staticmethod
    def _shannon_entropy(data, iterator):
        """
        Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
        This calculates the shannon entropy of a given array of bytes
        """
        if not data:
            return 0
        entropy = 0
        for x in iterator:
            p_x = float(data.count(x))/len(data)
            if p_x > 0:
                entropy += - p_x*math.log(p_x, 2)
        return entropy

    @staticmethod
    def _get_strings_of_set(word, char_set, threshold=20):
        """
        Get all the strings of threshold length or longer that belong to a specific charset out of word
        """
        count = 0
        letters = ""
        strings = []
        for char in word:
            if char in char_set:
                letters += char
                count += 1
            else:
                if count > threshold:
                    strings.append(letters)
                letters = ""
                count = 0
        if count > threshold:
            strings.append(letters)
        return strings

    def _find_entropy(self, printable_diff, commit_time, branch_name, prev_commit, blob, commitHash):
        """
        Search a blob for high entropy strings
        """
        found_strings = []
        for line in printable_diff.split("\n"):
            for word in line.split():
                base64_strings = self._get_strings_of_set(word, BASE64_CHARS)
                hex_strings = self._get_strings_of_set(word, HEX_CHARS)
                for string in base64_strings:
                    b64Entropy = self._shannon_entropy(string, BASE64_CHARS)
                    if b64Entropy > 4.5:
                        found_strings.append(string)
                        printable_diff = printable_diff.replace(string, bcolors.make_warning(string))
                for string in hex_strings:
                    hexEntropy = self._shannon_entropy(string, HEX_CHARS)
                    if hexEntropy > 3:
                        found_strings.append(string)
                        printable_diff = printable_diff.replace(string, bcolors.make_warning(string))
        if len(found_strings) > 0:
            finding = dict(
                path = blob.b_path if blob.b_path else blob.a_path,
                reason = "High Entropy",
                found_strings = found_strings,
                commit_hash = prev_commit.hexsha,
                branch = branch_name,
                date = commit_time,
                commit_message = prev_commit.message,            
                diff = printable_diff      
            )
            self.findings.append(finding)

    def _regex_check(self, printable_diff, commit_time, branch_name, prev_commit, blob, commitHash):
        """
        Search a given piece of source code for strings that match predefined regex checks
        """
        for key, regex in self.regexes.items():
            found_strings = regex.findall(printable_diff)
            for found_string in found_strings:
                printable_diff = printable_diff.replace(found_string, bcolors.make_warning(found_string))
            if found_strings:
                finding = dict(
                    path = blob.b_path if blob.b_path else blob.a_path,
                    reason = f"Regex Match: {key}",
                    found_strings = found_strings, 
                    commit_hash = prev_commit.hexsha,
                    branch = branch_name,
                    date = commit_time,          
                    commit_message = prev_commit.message,                                     
                    diff = printable_diff
                )
                self.findings.append(finding)
                