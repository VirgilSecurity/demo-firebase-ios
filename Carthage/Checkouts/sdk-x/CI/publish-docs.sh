#!/bin/bash
#
# Copyright (C) 2015-2016 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#PUBLISH_DOCS
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

# Settings
REPO_PATH=https://github.com/VirgilSecurity/sdk-x.git
HTML_PATH_DST="${TRAVIS_BUILD_DIR}/docs"
CHANGESET=$(git rev-parse --verify HEAD)

# Get a clean version of the HTML documentation repo.
rm -rf ${HTML_PATH_DST}
mkdir -p ${HTML_PATH_DST}
git clone -b gh-pages "${REPO_PATH}" --single-branch ${HTML_PATH_DST}

INFOPLIST_FILE_PATH="${TRAVIS_BUILD_DIR}/VirgilSDK/Info.plist"

# Define SDK versions
VIRGIL_SDK_VERSION="v"$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" "${INFOPLIST_FILE_PATH}")
VIRGIL_SDK_HTML_PATH_DST="${HTML_PATH_DST}/${VIRGIL_SDK_VERSION}"

# Generate the HTML documentation.
VIRGIL_SDK_HTML_PATH_DST=${VIRGIL_SDK_HTML_PATH_DST} ./CI/generate-docs.sh

# Generate root HTML file
function get_dir_names {
    local DIRS=`find "$1" -maxdepth 1 -type d -name "$2"`
    local DIR_NAMES=()
    for dir in ${DIRS}; do
        DIR_NAMES+=("${dir#${1}/}")
    done
    echo ${DIR_NAMES[*]}
}

cat >"${HTML_PATH_DST}/index.html" <<EOL
<!DOCTYPE HTML>
<html>
   <head>
        <meta charset="utf-8">
        <title>Virgil Security iOS SDK</title>
   </head>
   <body>
        Virgil Security iOS SDK
        <ul>
EOL

for dir in `get_dir_names "${VIRGIL_SDK_HTML_PATH_DST}/.." "v*"`; do
    echo "<li><p><a href=\"${dir}/index.html\">${dir}</a></p></li>" >> "${HTML_PATH_DST}/index.html"
done

cat >>"${HTML_PATH_DST}/index.html" <<EOL
        </ul>
   </body>
</html>
EOL
