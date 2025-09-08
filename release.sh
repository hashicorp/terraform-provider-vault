#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0
#
# #############################################################################
#
#   Interactive Release Helper
#
#   This script guides you through the pre-release validation steps for
#   creating a new release. It ensures that the correct commit is chosen,
#   the version is valid, and the target environment is explicitly confirmed.
#
#   It is designed to be run manually to provide a series of safety checks
#   before a release is formally tagged and deployed.
#
#   Prerequisites:
#     Set the BOB_GITHUB_TOKEN environment variable.
#
#   Usage:
#     ./release.sh [BRANCH]
#
#   Arguments:
#     BRANCH (optional): The branch or Git reference to release from.
#                        Defaults to 'origin/main' if not specified.
#
#   Workflow:
#     1. Fetches the latest state from the 'origin' remote.
#     2. Displays the target commit for final review and asks for confirmation.
#     3. Reads the version number from the 'version/VERSION' file within that commit.
#     4. Constructs a new tag (e.g., v1.2.3) based on the version file.
#     5. Verifies that this tag does not already exist locally or on the remote.
#     6. Asks for final confirmation before proceeding with the release tag.
#     7. Prompts for a target environment (Staging or Production) with an
#        extra confirmation step for the production environment.
#
# #############################################################################

set -e

# SLACK_CHANNEL code is duplicated in ./release/ci.hcl
SLACK_CHANNEL="C03RXFX5M4L"
# BRANCH allow override of default branch with an optional argument
BRANCH="${1:-origin/main}"
# LOCAL_BRANCH bob needs this trimmed
LOCAL_BRANCH="${BRANCH#origin/}"
# VERSION_PATH path to the version file
VERSION_PATH="${BRANCH}:version/VERSION"

YLW=$(tput setaf 3) # yellow
RST=$(tput sgr0) # reset

log_info() {
  printf "==> %s\n" "$@"
}
log_warn() {
  printf "[!] Warning: %s\n" "$@"
}
log_error() {
  printf "[X] Error: %s\n" "$@"
}
prompt() {
  printf "[?] %s" "$@ "
}

# fail if this is not set
if [[ -z "$BOB_GITHUB_TOKEN" ]]; then
  log_error "BOB_GITHUB_TOKEN is not set"
  exit 1
fi

# show the latest commit of BRANCH to user for manual validation
log_info "Fetching default release branch '${BRANCH}'..."
git fetch origin
RELEASE_SHA=$(git rev-parse ${BRANCH})
git log -n 1 ${RELEASE_SHA}

prompt "Do you want to release commit ${YLW}${RELEASE_SHA}${RST}? (y/n): "
read input
if [[ "$input" != "y" ]]; then
  echo
  exit 0
fi

VERSION=$(git show ${VERSION_PATH})
TAG_NAME="v${VERSION}"
if [[ -z "$VERSION" ]]; then
  log_error "No version found at path '${VERSION_PATH}'"
  exit 1
fi

log_info "Got version ${YLW}${VERSION}${RST} from ${VERSION_PATH}"

# show last release tag
LATEST_TAG=$(git ls-remote --tags --sort="v:refname" origin | awk -F/ '{print $3}' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | tail -n 1)
log_info "Latest semantic version tag on remote 'origin': ${YLW}${LATEST_TAG}${RST}"

# validate new tag is available
log_info "Fetching latest tags from remote 'origin'..."
git fetch origin --tags
if git rev-parse --verify "refs/tags/${TAG_NAME}" >/dev/null 2>&1; then
  log_error "Git tag ${TAG_NAME} already exists"
  exit 1
fi
log_info "Git tag ${YLW}${TAG_NAME}${RST} is available"

prompt "Do you want to release tag ${YLW}${TAG_NAME}${RST}? (y/n): "
read input
if [[ "$input" != "y" ]]; then
  echo
  exit 0
fi

TARGET_ENV=""

while true; do
  echo "Promotion environments:"
  echo -e "  [s] Staging"
  echo -e "  [p] Production"
  prompt "Select release environment (s/p): "
  read env_choice

  case $env_choice in
    s|S )
      TARGET_ENV="staging"
      break
      ;;
    p|P )
      prompt "You are about to deploy to PRODUCTION. Are you sure? (y/n): "
      read confirm
      if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        TARGET_ENV="production"
        break
      else
        log_warn "Production deployment aborted"
        # The loop will continue, re-prompting the user.
      fi
      ;;
    * )
      log_error "Invalid option. Please choose 's' or 'p'. CTRL-C to exit."
      # The loop will continue, re-prompting the user.
      ;;
  esac
done
log_info "Targeting deployment to ${YLW}${TARGET_ENV}${RST}..."

bob trigger-promotion \
  --product-name terraform-provider-vault \
  --org hashicorp \
  --repo terraform-provider-vault \
  --branch ${LOCAL_BRANCH?} \
  --product-version ${VERSION?} \
  --sha "${RELEASE_SHA?}" \
  --environment terraform-provider-vault \
  --slack-channel ${SLACK_CHANNEL?} \
  ${TARGET_ENV?}
