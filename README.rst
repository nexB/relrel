RelRel
======

RelRel is a library for reliable releasing on GitHub to create releases and
upload files there coping with the unfortunate quirks and unreliability of this
GitHub service.

RelRel creates releases and uploads files (aka. assets) and can verify that
the uploads are reliably published and retries if things are incomplete
(which is an unfortunate thing on GitHub).

It differs from other tools because it verifies checksums for uploaded files to
reliably verify that the file has been uploaded and retries (deleting partial or
incorrect upload) if not.

Based on https://github.com/google/github-release-retry and heavily modified.
Created originally by @paulthomson


The problem
-----------

As of 2021, GitHub exposes two APIs (v3 and V4 GraphQL) to interact with
releases. In practice, none of these APIs work flawlessly and using both is
needed for reliable operations.  In addition because of the combination of API
rate limiting and the flakyness of the API, a file upload can and will often
fail to complete which leaving the "releas asset" in some undefined and
unusable state.  Uploaded files end up in backing Amazon S3 buckets in a way
that seems to have been designed to make it hard to access S3 directly.


The solution
------------

This library provides functions and a command line tool to:

1. Create or update a release on GitHub for a given tag.
2. Upload files (with checksum information) and verify that uploads are correct.
3. Delete and upload failed or incorrect uploads and retry until success.

It's goal is to be reliable and correctbefore being fast. The codestill tries to
run as fast as possible by staying polite and aligning its network call rates
with the GitHub API rate limiting feedback.

name: relrel
package_url: pkg:pypi/relrel
homepage_url: https://github.com/nexB/relrel
license: Apache-2.0

Install
-------

Requires Python 3.6+::

    pip install relrel


Usage
-----

You will need:

1. a GitHub token. Create this following these instructions:

Then use or export a GITHUB_TOKEN environment vaiable with the token value.

    export GITHUB_TOKEN=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX


From the command line, get help with::

    python -m relrel -h
    usage: github-release-retry [-h] --user USER --repo REPO --tag_name TAG_NAME
                                [--target_commitish TARGET_COMMITISH]
                                [--release_name RELEASE_NAME]
                                (--body_string BODY_STRING | --body_file BODY_FILE)
                                [--draft] [--prerelease]
                                [--github_api_url GITHUB_API_URL]
                                [--retry_limit RETRY_LIMIT]
                                [files [files ...]]



To create (or update) a GitHub release and uploads files to the release, use this:

1. Please set the GITHUB_TOKEN environment variable.
2. Run this::

    python -m relrel \
      --user-repo foo/hello-world \
      --tag_name v1.0 \
      --body_string "My first release." \
      <path to files or directry to upload>



Development
-----------

