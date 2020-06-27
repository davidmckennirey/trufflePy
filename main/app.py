from interface.cli import gen_arg_parser      
from argparse import Namespace
from git import Repo
from search.engine import SearchEngine
from regexes.searches import get_secret_regexes
import logging
import sys
import tempfile
from github import Github


logger = logging.getLogger(__name__)
_LOGGING_CONFIG = dict(
    style="{",
    format="\t".join(("{levelname}", "{message}")),
    stream=sys.stdout,
    level=logging.INFO
)


def local(args: Namespace):
    logger.info(f"Searching through local git repo at: {args.path}")
    repo = Repo(args.path)
    engine = SearchEngine(repo, get_secret_regexes(args.rules), args.include_paths, args.exclude_paths, args.since_commit, args.max_depth)
    engine.find_secrets(branch=args.branch, print_json=args.json)


def url(args: Namespace):
    logger.info(f"Searching through remote git repo at: {args.URL}")
    with tempfile.TemporaryDirectory() as temp_repo_dir:
        try:
            repo = Repo.clone_from(args.URL, temp_repo_dir)
        except:
            logger.error(f"Could not clone repo")
            sys.exit(1)
        engine = SearchEngine(repo, get_secret_regexes(args.rules), args.include_paths, args.exclude_paths, args.since_commit, args.max_depth)
        engine.find_secrets(branch=args.branch, print_json=args.json)


def github(args: Namespace):
    print("github") # TODO implement this


def trufflePy_main():
    parser = gen_arg_parser()
    args = parser.parse_args()
    logging.basicConfig(**_LOGGING_CONFIG)
    return args.func(args)