#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) nexb Inc., Google Inc., The github-release-retry Project Authors, and others
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Create a GitHub release and upload files reliably.
Based on https://github.com/google/github-release-retry and heavily modified.
Created originally by @paulthomson
"""

import argparse
import datetime
import hashlib
import os
import re
import sys
import time

from pathlib import Path

import attr
import requests

MAX_DELAY = 20


def remove_none_fields(mapping):
    return {k: v for k, v in mapping.items() if v is not None}


def log(message):
    print(message, file=sys.stderr)


class Serializable:

    def to_dict(self):
        return {k: v for k, v in attr.asdict(self).items() if not v}

    @classmethod
    def from_dict(cls, data):
        existing = attr.fields_dict(cls)
        kwargs = {k: v for k, v in data.items() if v and k in existing}
        return cls(**kwargs)


@attr.attributes
class Asset(Serializable):
    """
    An Asset represents an uploaded file attached to a release.
    """
    id = attr.ib(type=int, default=None, metadata={'help': 'GitHub ID.'})
    url = attr.ib(type=str, default=None, metadata={'help': 'Asset API URL.'})
    browser_download_url = attr.ib(type=str, default=None, metadata={'help': 'URL to download.'})
    name = attr.ib(type=str, default=None, metadata={'help': 'Filename.'})
    label = attr.ib(type=str, default=None, metadata={'help': 'Asset label.'})
    state = attr.ib(type=str, default=None, metadata={'help': 'GitHub asset state.'})
    size = attr.ib(type=int, default=None, metadata={'help': 'File size in bytes.'})

    def is_modified(self, file_path, ghapi=None):
        """
        Check if this remote asset is modified (e.g. not correctly uploaded) and
        out of sync with a local `filepath` Path using multiple techniques,
        including remote checks if `ghapi` is provided.
        """
        # check the simple and obvious first
        size = file_path.stat().st_size
        if (self.name != file_path.name
            or self.size != size
            or self.state != "uploaded"
        ):
            return True

        if ghapi:
            with open(file_path, 'rb') as fi:
                content = fi.read()
                local_md5 = hashlib.md5(content).hexdigest()
            return self.is_modified_using_etag(ghapi, local_md5)

        return False

    def is_modified_using_etag(self, ghapi, md5):
        """
        Return True if this asset remote is modified (e.g. not matching the
        provided md5 hex checksum)
        """
        etag = f'"{md5}"'
        headers = {'User-Agent': f"{self.user_repo}", 'If-None-Match': f'{etag}'}
        url = self.browser_download_url
        if not url:
            log(f'Cannot check asset: {self.name} browser_download_url is missing.')
            return True

        response = ghapi.send_request(
            GET,
            url=url,
            headers=headers,
            honor_rate_limits=False,
            # we do not want the actual contents
            stream=True,
        )

        # 304: Not Modified
        return response.status_code != requests.code.not_modified  # NOQA


def clean_upload_url(url):
    if url:
        # FIXME: Upload URL is a URI template and we should decode it using the proper library
        # it looks like:
        #  https://uploads.github.com/repos/octocat/Hello-World/releases/1/assets{?name,label}
        # We want the part before {.
        return url.split("{")[0]


def build_assets_by_filename(assets):
    """
    Convert a list of asset mappings to a mapping of {filename: Asset object}
    """
    if not assets:
        return {}
    assets_by_filename = {}
    for asset in assets:
        a = Asset.from_dict(asset)
        assets_by_filename[a.name] = a
    return assets_by_filename


@attr.attributes
class Release(Serializable):
    """
    A Release represents a repo release.
    """
    id = attr.ib(
        type=int,
        default=None,
        metadata={'help': 'GitHub ID.'},
    )
    upload_url = attr.ib(
        type=str,
        default=None,
        converter=clean_upload_url,
        metadata={'help': 'API URL to upload assets.'},
    )
    html_url = attr.ib(
        type=str,
        default=None,
        metadata={'help': 'HTML web page URL.'},
    )
    tag_name = attr.ib(
        type=str,
        default=None,
        metadata={'help': 'Release tag.'},
    )
    assets = attr.attrib(
        type=dict,
        default=attr.Factory(dict),
        converter=build_assets_by_filename,
        metadata={'help': 'Mapping of {filename: Asset object}'},
    )

    target_commitish = attr.ib(type=str, default=None, metadata={'help': 'Target commit to use.'})
    name = attr.ib(type=str, default=None, metadata={'help': 'Release name.'})
    body = attr.ib(type=str, default=None, metadata={'help': 'Release body text (markdown)'})
    draft = attr.ib(type=bool, default=False, metadata={'help': 'True if this is a draft release.'})
    prerelease = attr.ib(type=bool, default=False, metadata={'help': 'True if this is a prerelease.'})

    def to_dict(self):
        td = Serializable.to_dict(self)
        td.pop('assets', None)
        return td

    def publish(self, ghapi, file_paths):
        """
        Create or update this release at GitHub and upload the `file_paths` list
        of paths.
        """
        assert self.tag_name, "tag_name must be provided in release: {release}"
        missing_files = list(filter(lambda p: not p.is_file(), file_paths))
        assert not missing_files, f'File are missing: {missing_files}'

        # get existing releases
        releases = ghapi.get_releases_by_tag()
        remote_release = releases.get(self.tag_name)
        if not remote_release:
            # create if it does not exist
            remote_release = ghapi.create_release(self)
        # loop through files and upload
        for file_path in file_paths:
            remote_release.upload_file(ghapi, file_path)

    def get_published_urls(self, ghapi):
        """
        Return a list of file download URLs for this release scraped from the
        release HTML web page.
        """
        if not self.html_url:
            log('Cannot get published assets: html_url is missing.')
            return []

        headers = {'User-Agent': f"{self.user_repo}"}
        response = ghapi.send_request(GET, url=self.html_url, headers=headers)
        if response.status_code != requests.codes.ok:  # NOQA
            raise UnexpectedResponseError(response)

        get_urls = re.compile('href="(/[^"]+/releases/download/[^"]+)"').findall
        return [f'https://github.com{l}' for l in get_urls(response.text)]

    def validate_publication(self, ghapi):
        """
        Check that API assets match the web page assets.
        """
        raise NotImplementedError

    def upload_file(self, ghapi, file_path):
        """
        Upload a single file to this release.
        """
        log(f"Uploading: {file_path.name}")

        retry_count = 0
        wait_time = 2

        while True:
            remote_asset = self.assets.get(file_path.name)
            if remote_asset:
                if not remote_asset.is_modified(file_path, ghapi):
                    log(f"The asset for {file_path.name} has the correct md5, size and state. Asset done.")
                    break

                log(f"The asset for {file_path.name} does not match local file and is being deleted.")
                response = ghapi.delete_asset(remote_asset.id)
                if response.status_code != requests.codes.no_content:  # NOQA
                    log(f"Ignoring failed deletion: {response}")

            # now we can create an asset
            log(f"The asset for {file_path.name} does not exists and will be uploaded.")
            # Asset does not exist or has now been deleted.

            if retry_count >= ghapi.retry_limit:
                raise HitRetryLimitError(f"Hit upload retry limit for {file_path.name}")

            if retry_count > 0:
                log(f"  Waiting {wait_time} seconds before retrying upload.")
                time.sleep(wait_time)

            retry_count += 1
            wait_time = wait_time * 2

            try:
                new_asset = ghapi.upload_asset(file_path, self.upload_url)
                if new_asset:
                    self.assets[file_path.name] = new_asset
                    break
            except Exception as ex:
                log(f"  Ignoring upload exception: {ex}")

            # And now we loop.


GET = 'get'
POST = 'post'
DELETE = 'delete'

VERBS = {
    GET: requests.get,
    POST:requests.post,
    DELETE:requests.delete,
}


def as_dt(reset):
    return reset and datetime.datetime.fromtimestamp(reset, datetime.timezone.utc)


@attr.attributes
class RateLimiter:
    """
    A RateLimiter is used to track GitHub API calls rate limiting.
    """
    # See https://docs.github.com/en/free-pro-team@latest/rest/overview/resources-in-the-rest-api#rate-limiting
    limit = attr.attrib(
        type=int,
        default=60,
        metadata={'help': 'maximum number of requests permitted per hour.'},
    )

    remaining = attr.attrib(
        type=int,
        default=60,
        metadata={'help': ' number of requests remaining in rate limit window.'},
    )

    reset = attr.attrib(
        type=datetime.datetime,
        default=None,
        converter=as_dt,
        metadata={
            'help': 'datetime.datetime object for the time at which the '
                'current rate limit window resets in UTC epoch seconds.',
        }
    )

    def wait(self):
        """
        Wait to make an API call if needed.
        """
        if self.remaining > 0 :
            return
        sleep_for = self.reset - datetime.datetime.now(datetime.timezone.utc)
        if sleep_for > 0:
            log(f'API rate-limit induced sleep for {sleep_for} seconds.')
            time.sleep(sleep_for + 1)

    @classmethod
    def from_headers(cls, headers):
        """
        Return a RateLimiter object from a mapping of HTTP headers or None.
        """
        keys = 'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset',

        headers = {k.lower(): v for k, v in headers.items()}

        if not all(k in headers for k in keys):
            return
        limit = int(headers['x-ratelimit-limit'])
        remaining = int(headers['x-ratelimit-remaining'])
        reset = int(headers['x-ratelimit-reset'])

        return cls(limit=limit, remaining=remaining, reset=reset)


@attr.attributes
class GithubApi:

    github_api_url = 'https://api.github.com'

    user_repo = attr.ib(
        type=str,
        default=None,
        metadata={'help': 'GitHub user/repo or org/repo.'},
    )
    token = attr.ib(
        type=str,
        default=None,
        metadata={'help': 'GitHub token'},
    )
    retry_limit = attr.ib(
        type=int,
        default=None,
        metadata={'help': 'Maximum number of API retries.'},
    )
    rate_limiter = attr.ib(
        type=RateLimiter,
        default=None,
        metadata={'help': 'RateLimiter object to manage API rate limits.'},
    )

    def headers_v3(self):
        return {
            "Accept": "application/vnd.github.v3.text-match+json",
            "Authorization": f"token {self.token}",
            # "User-Agent": f"{self.user_repo}",
        }

    def get_latest_rate_limiter(self):
        """
        Return the latest RateLimiter object from calling the GitHub API.
        """
        response = self.send_request(
            GET,
            url=f'{self.github_api_url}/rate_limit',
            headers=self.headers_v3(),
            honor_rate_limits=False,
        )
        if response.status_code != requests.codes.ok:  # NOQA
            raise UnexpectedResponseError(response)

        return RateLimiter.from_headers(response.headers)

    def send_request(
        self,
        verb,
        url,
        headers=None,
        honor_rate_limits=True,
        _delay=0,
        **kwargs,
    ):
        """
        Send a request with ``verb`` (e.g. get, post, delete as one of ``VERBS``
        values) to ``url`` with a ``headers`` mapping of headers and ``kwargs``.
        Wait until authorized per rate limit policy if ``honor_rate_limits`` is
        True.
        """
        time.sleep(_delay)
        log(f'\nRequest for: {url}')
        if honor_rate_limits:
            if self.rate_limiter:
                self.rate_limiter.wait()
            else:
                self.rate_limiter = self.get_latest_rate_limiter()

        method = VERBS[verb]
        response = method(url=url, headers=headers, **kwargs)

        status = response.status_code
        if status == 429 and _delay < MAX_DELAY:
            # too many requests: start some exponential delay
            increased_delay = (_delay * 2) or 1

            return self.send_request(
                verb=verb,
                url=url,
                headers=headers,
                honor_rate_limits=honor_rate_limits,
                _delay=increased_delay,
                **kwargs,
            )

        response_headers = {k.lower(): v for k, v in response.headers.items()}
        rl = RateLimiter.from_headers(response_headers)
        if rl:
            self.rate_limiter = rl
        return response

    def create_release(self, release):
        """
        Post a ``release`` Release and return the created Release object.
        """
        response = self.send_request(
            POST,
            url=f"{self.github_api_url}/repos/{self.user_repo}/releases",
            headers=self.headers_v3(),
            json=release.to_dict(),
        )
        if response.status_code != requests.codes.created:  # NOQA
            log(f"Failed  to create release")
            raise UnexpectedResponseError(response)

        return Release.from_dict(response.json())

    def get_releases_by_tag(self):
        """
        Return a mapping of {tag_name: Release}.
        """
        log(f'Fetching releases')

        response = self.send_request(
            GET,
            url=f"{self.github_api_url}/repos/{self.user_repo}/releases",
            headers={},  # self.headers_v3(),
        )

        if response.status_code != requests.codes.ok:  # NOQA
            raise UnexpectedResponseError(response)

        log(f'Fetched releases')

        releases_by_tag = {}
        for rel in response.json():
            release = Release.from_dict(rel)
            releases_by_tag[release.tag_name] = release
        return releases_by_tag

    def delete_asset(self, asset_id):
        response = self.send_request(
            DELETE,
            url=f"{self.github_api_url}/repos/{self.user_repo}/releases/assets/{asset_id}",
            headers={**self.headers_v3(), "Content-type": "application/json"},
        )
        if response.status_code != requests.codes.ok:  # NOQA
            raise UnexpectedResponseError(response)
        return response

    def upload_asset(self, file_path, upload_url):
        # FIXME: Upload URL is a URI template and we should decode it using the proper library
        # it looks like:
        #  https://uploads.github.com/repos/octocat/Hello-World/releases/1/assets{?name,label}
        # We want the part before {.
        hlabel = get_hashes_label(file_path)
        upload_url = f"{upload_url}?name={file_path.name}&label={file_path.name}+{hlabel}"

        headers = {
            **self.headers_v3(),
            "Content-Type": "application/octet-stream",
        }
        with file_path.open(mode="rb") as fi:
            response = self.send_request(
                POST,
                url=upload_url,
                headers=headers,
                data=fi,
            )

            if response.status_code != requests.codes.created:  # NOQA
                log(f"  Ignoring failed upload: {response}")
                return

            return Asset.from_dict(response.json())


def get_hashes(file_path):
    """
    Return a mapping of checksums for a file_path.
    """
    with open(file_path, 'rb') as fi:
        content = fi.read()
        return dict(
            md5=hashlib.md5(content).hexdigest(),
            sha256=hashlib.sha256(content).hexdigest(),
        )


def get_hashes_label(file_path):
    """
    Return a string to use in an asset label and that contains checksums.
    """
    from urllib.parse import quote_plus
    hashes = get_hashes(file_path)
    return quote_plus(f" , md5:{hashes['md5']} , sha256:{hashes['sha256']}")


class MissingTokenError(Exception):
    pass


class MissingFilesError(Exception):

    def __init__(self, missing_paths):
        self.missing_paths = missing_paths
        missing_paths_str = [str(p) for p in missing_paths]
        missing_paths_joined = "\n" + "\n".join(missing_paths_str) + "\n"
        super().__init__(f"Missing: {missing_paths_joined}")


class UnexpectedResponseError(Exception):

    def __init__(self, response):
        self.response = response
        super().__init__(f"Unexpected response: {response.__dict__}")


class HitRetryLimitError(Exception):
    pass


def publish_release(
    user_repo,
    token,
    retry_limit,
    body_text,
    tag_name,
    target_commitish,
    name,
    draft,
    prerelease,
    file_paths,
):
    """
    Publish a release.
    """

    ghapi = GithubApi(
        user_repo=user_repo,
        token=token,
        retry_limit=retry_limit,
    )

    release = Release(
        tag_name=tag_name,
        target_commitish=target_commitish,
        name=name,
        body=body_text,
        draft=draft,
        prerelease=prerelease,
    )

    release.publish(ghapi, file_paths)


class ArgumentDefaultsWithRawDescriptionHelpFormatter(
    argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter
):
    pass


def main_with_args(args):

    parser = argparse.ArgumentParser(
        description="""Create a GitHub release (if it does not already exist) and upload file_paths to the release.
Please set the GITHUB_TOKEN environment variable.
EXAMPLE:
relrel\\
  --user-repo paul/hello-world \\
  --tag_name v1.0 \\
  --target_commitish 448301eb \\
  --body_string "My first release." \\
  hello-world.zip RELEASE_NOTES.txt
""",
        formatter_class=ArgumentDefaultsWithRawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--user_repo",
        help="Required: The GitHub user/repo or organization/repo for the repo.",
        type=str,
        required=True,
    )

    parser.add_argument(
        "--tag_name",
        help="Required: The name of the tag to create or use.",
        type=str,
        required=True,
    )

    parser.add_argument(
        "--target_commitish",
        help="The commit-ish value where the tag will be created. Unused if the tag already exists. ",
        type=str,
        default=None,
    )

    parser.add_argument(
        "--release_name",
        help="The name of the release. Leave unset to use the tag_name (recommended). ",
        type=str,
        default=None,
    )

    # --body_string XOR --body_file
    body_group = parser.add_mutually_exclusive_group(required=False)
    body_group.add_argument(
        "--body_string",
        help="Required (or use --body_file): Text describing the release. Ignored if the release already exists.",
        type=str,
    )
    body_group.add_argument(
        "--body_file",
        help="Required (or use --body_string): Text describing the release, which will be read from BODY_FILE. Ignored if the release already exists.",
        type=str,
    )

    parser.add_argument(
        "--draft",
        help="Creates a draft release, which means it is unpublished. ",
        action="store_true",
    )

    parser.add_argument(
        "--prerelease",
        help="Creates a prerelease release, which means it will be marked as such. ",
        action="store_true",
    )

    parser.add_argument(
        "--retry_limit",
        help="The number of times to retry creating/getting the release and/or uploading each file. ",
        type=int,
        default=10,
    )

    parser.add_argument(
        "file_paths",
        metavar="file_paths",
        type=str,
        nargs="*",
        help="The file_paths to upload to the release.",
    )

    parsed_args = parser.parse_args(args)

    token = os.environ.get("GITHUB_TOKEN", None)
    if not token:
        raise MissingTokenError("Please set the GITHUB_TOKEN environment variable.")

    body_text = None
    if parsed_args.body_string:
        body_text = parsed_args.body_string
    elif parsed_args.body_file:
        body_text = Path(parsed_args.body_file).read_text(
            encoding="utf-8", errors="ignore"
        )

    files_str = parsed_args.file_paths
    file_paths = [Path(f) for f in files_str]

    publish_release(
        user_repo=parsed_args.user_repo,
        token=token,
        retry_limit=parsed_args.retry_limit,
        body_text=body_text,
        tag_name=parsed_args.tag_name,
        target_commitish=parsed_args.target_commitish or None,
        name=parsed_args.release_name or None,
        draft=parsed_args.draft or False,
        prerelease=parsed_args.prerelease or False,
        file_paths=file_paths,
    )


def main():
    return main_with_args(sys.argv[1:])


if __name__ == "__main__":
    main()
