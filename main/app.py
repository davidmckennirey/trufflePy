from interface.cli import gen_arg_parser      
from argparse import Namespace
from git import Repo
from search.engine import SearchEngine
from regexes.searches import get_secret_regexes
import sys
import tempfile
from github import Github


def local(args: Namespace):
    print(f"Searching through local git repo at: {args.path}\n")
    repo = Repo(args.path)
    engine = SearchEngine(repo, get_secret_regexes(args.rules), args.include_paths, args.exclude_paths, args.since_commit, args.max_depth)
    engine.find_secrets(branch=args.branch, print_json=args.json, skip_entropy=args.skip_entropy, skip_regex=args.skip_regex)


def url(args: Namespace):
    print(f"Searching through remote git repo at: {args.URL}\n")
    with tempfile.TemporaryDirectory() as temp_repo_dir:
        try:
            repo = Repo.clone_from(args.URL, temp_repo_dir)
        except:
            print(f"ERROR: Could not clone repo")
            sys.exit(1)
        engine = SearchEngine(repo, get_secret_regexes(args.rules), args.include_paths, args.exclude_paths, args.since_commit, args.max_depth)
        engine.find_secrets(branch=args.branch, print_json=args.json, skip_entropy=args.skip_entropy, skip_regex=args.skip_regex)


def github(args: Namespace):
    print(f"Searching through repos of Github user: {args.user}\n")
    try:
        g = Github(args.key)
    except:
        print("ERROR: Could not connect to Github with provided key")
        sys.exit(1)
    try:
        for github_repo in g.get_user(args.user).get_repos():
            args.URL = github_repo.clone_url
            url(args)
    except:
        print(f"ERROR: Could not get Github repos for user {args.user}")


def trufflePy_main():
    parser = gen_arg_parser()
    args = parser.parse_args()
    return args.func(args)