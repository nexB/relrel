#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2020 The github-release-retry Project Authors
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

import json
import os
from typing import Any

import requests
import requests_mock  # type: ignore

from relrel import GithubApi
from relrel import Release


class GitHubTestCase:

    @classmethod
    def get_fixture(cls, filename: str) -> Any:
        location = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
        fixture = os.path.join(location, "data", filename)
        with open(fixture, encoding="utf-8", errors="ignore") as json_file:
            data = json.load(json_file)
            return data


rate_limit_api = {
  "resources": {
    "core": {
      "limit": 60,
      "remaining": 59,
      "reset": 1632405268,
      "used": 1,
      "resource": "core"
    },
    "graphql": {
      "limit": 0,
      "remaining": 0,
      "reset": 1632405271,
      "used": 0,
      "resource": "graphql"
    },
    "integration_manifest": {
      "limit": 5000,
      "remaining": 5000,
      "reset": 1632405271,
      "used": 0,
      "resource": "integration_manifest"
    },
    "search": {
      "limit": 10,
      "remaining": 10,
      "reset": 1632401731,
      "used": 0,
      "resource": "search"
    }
  },
  "rate": {
    "limit": 60,
    "remaining": 59,
    "reset": 1632405268,
    "used": 1,
    "resource": "core"
  }
}


class TestGithubApi(GitHubTestCase):

    @staticmethod
    def test_github_api_invalid_token() -> None:
        github = GithubApi(
            user_repo="google/github-release-retry",
            token="INVALID_TOKEN",
            retry_limit=10,
        )
        assert github.token == "INVALID_TOKEN"

        release = Release(
            tag_name="v1.0",
            target_commitish=None,
            name=None,
            body="Test",
            draft=None,
            prerelease=None,
        )

        github_release = github.create_release(release)

        assert github_release.status_code == requests.codes.unauthorized  # NOQA

    def test_create_release_with_mock_requests_already_exists(self) -> None:
        github = GithubApi(# noqa: S106
            user_repo="google/github-release-retry",
            token="VALID_MOCK_TOKEN",
            retry_limit=10,
        )
        assert github.token == "VALID_MOCK_TOKEN"

        release = Release(
            tag_name="v1.0",
            target_commitish=None,
            name=None,
            body="Test",
            draft=None,
            prerelease=None,
        )

        with requests_mock.Mocker() as mocker:
            mocker.register_uri(
                "GET",
                f"{github.github_api_url}/rate_limit",
                json=rate_limit_api,
            )

            mocker.register_uri(
                "POST",
                f"{github.github_api_url}/repos/{github.user_repo}/releases",
                json=self.get_fixture("release_already_exists.json"),
                status_code=requests.codes.unprocessable_entity,  # NOQA
            )

            mocker.register_uri(
                "GET",
                f"{github.github_api_url}/repos/{github.user_repo}/releases/tags/{release.tag_name}",
                json=self.get_fixture("get_release_by_tag.json"),
            )

            github_release = github.create_release(release)

            assert github_release.status_code == requests.codes.unprocessable_entity  # NOQA

    def test_get_releases_by_tag_mock_data(self) -> None:
        github = GithubApi(# noqa: S106
            user_repo="google/github-release-retry",
            token="VALID_MOCK_TOKEN",
            retry_limit=10,
        )
        assert github.token == "VALID_MOCK_TOKEN"

        release = Release(
            tag_name="v1.0",
            target_commitish=None,
            name=None,
            body="Test",
            draft=None,
            prerelease=None,
        )

        with requests_mock.Mocker() as mocker:
            mocker.register_uri(
                "GET",
                f"{github.github_api_url}/rate_limit",
                json=rate_limit_api,
            )

            mocker.register_uri(
                "GET",
                f"{github.github_api_url}/repos/{github.user_repo}/releases/tags/{release.tag_name}",
                json=self.get_fixture("get_release_by_tag.json"),
                status_code=requests.codes.ok,  # NOQA
            )

            github_release = github.get_releases_by_tag()

            assert github_release.status_code == requests.codes.ok  # NOQA
