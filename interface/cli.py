"""
Command Line Interface to control the script
"""

from argparse import ArgumentParser
from os import environ
from main import app

def gen_arg_parser() -> ArgumentParser:
     main = ArgumentParser(description='Find secrets hidden in the depths of git and pycache!')
     subparsers = main.add_subparsers(title="Git source")

     # Main searching arguments
     main.add_argument("-j", "--json", dest="json", action="store_true", help="Output in JSON", default=False)
     main.add_argument("-r", "--rules", dest="rules", help="Ignore default regexes and source from json list file", default=None)
     main.add_argument("-s", "--since-commit", dest="since_commit", help="Only scan from a given commit hash", default=None)
     main.add_argument("-m", "--max-depth", dest="max_depth", help="The max commit depth to go back when searching for secrets")
     main.add_argument("-b", "--branch", dest="branch", help="Name of the branch to be scanned", default=None)
     main.add_argument('-i', '--include-paths', type=str, metavar='INCLUDE_PATHS_FILE', default=None,
                         help='File with regular expressions (one per line), at least one of which must match a Git '
                              'object path in order for it to be scanned; lines starting with "#" are treated as '
                              'comments and are ignored. If empty or not provided (default), all Git object paths are '
                              'included unless otherwise excluded via the --exclude_paths option.', dest="include_paths")
     main.add_argument('-x', '--exclude-paths', type=str, metavar='EXCLUDE_PATHS_FILE', default=None,
                         help='File with regular expressions (one per line), none of which may match a Git object path '
                              'in order for it to be scanned; lines starting with "#" are treated as comments and are '
                              'ignored. If empty or not provided (default), no Git object paths are excluded unless '
                              'effectively excluded via the --include_paths option.', dest="exclude_paths")
     main.add_argument("--skip-entropy", action="store_true", default=False, help="Skip doing entropy checks")
     main.add_argument("--skip-regex", action="store_true", default=False, help="Skip doing regex checks")


     # Local Git repo
     local = subparsers.add_parser("local", help="Search through a local git repo")
     local.add_argument("path", help="Path to the local git repo to search within")
     local.set_defaults(func=app.local)

     # Remote Git repo (via URL)
     url = subparsers.add_parser("url", help="Search through a remote git repo")
     url.add_argument("URL", help="Full URL path to git repo to search within")
     url.set_defaults(func=app.url)

     # Github user
     github = subparsers.add_parser("github", help="Search through Github user's public repos")
     github.add_argument("-k", "--key", help="Github API key (Defaults to GITHUB_KEY envrionment variable if not supplied)", default=environ.get('GITHUB_KEY', None)) # TODO: Add check for empty github key
     github.add_argument("user", help="Username of Github user to search within their repos.")
     github.set_defaults(func=app.github)

     # TODO: Add Gitlab Support
     # TODO: Add Bitbucket support
     return main

