# trufflePy
Find secrets hidden in the depths of git (now improved!)

This tool is a unificiation and continuation of the great work done by @dxa4481 with truffleHog, and @veggiedefender with his pycache secrets research. This project would not have been possible if were not for the amazing groundwork laid out by these two.

This tool searches through *every* single git diff in a git repository for secrets, by looking for both high entropy strings and high signal regex matches. Thanks to the help of uncompyle6, it can also look through pycache files for these secrets as well. It currently supports three operating modes; local, remote (url), and Github.

## Usage

TODO finish this