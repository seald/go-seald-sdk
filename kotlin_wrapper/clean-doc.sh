#!/bin/bash -eu

echo "Running 'clean-doc.sh' ..."

# Create clean output dir for doc
rm -rf ./doc
mkdir -p ./doc

# Copy stuff from the output of Dokka into the final directory, with cleaner file tree
cp -r ./seald_sdk/build/dokka/gfm/seald_sdk/io.seald.seald_sdk ./doc/seald-sdk-android

# Some regexes are more complex than it should be (using '[(]' instead of just '(', '*' instead of '+', ...), because it looks like sed can be more finicky than usual regex engines

# Change the first-level header of package index, so it is readable in the VuePress sidebar
sed -i.bak 's|# Package-level declarations|# Seald SDK for Android|' ./doc/seald-sdk-android/index.md

# Remove fragments header from dokka as it messes with VuePress title detection
find ./doc/seald-sdk-android -type f -name "*.md" -exec sh -c "\
 sed -i.bak 's|^//\[seald_sdk\].*||' {} ; \
" \;

# Remove useless crap put in the markdown by dokka
find ./doc/seald-sdk-android -type f -name "*.md" -exec sh -c "\
 sed -i.bak 's|^\[androidJvm\]\\\\$||' {} ; \
 sed -i.bak 's|^androidJvm$||' {} ; \
 sed -i.bak 's|\[androidJvm\]<br>||' {} ; \
" \;

# Fix weird links that dokka sometime produces in index.md files (https://github.com/Kotlin/dokka/issues/1548)
find ./doc/seald-sdk-android -type f -name "*.md" -exec sh -c "\
 sed -i.bak 's|.md#-\?[0-9]\+%2FProperties%2F[0-9]\+|.md#properties|g' {} ; \
 sed -i.bak 's|.md#-\?[0-9]\+%2FFunctions%2F[0-9]\+|.md#functions|g' {} ; \
" \;

# Fix :::warning tags for vuepress, and lists, that dokka breaks
find ./doc/seald-sdk-android -type f -name "*.md" -exec sh -c "\
 sed -i.bak 's|^:::\([a-z]\+\) |:::\1\n|' {} ; \
 sed -i.bak 's| :::$|\n:::|' {} ; \
 sed -i.bak '/^-\s*$/{N;s/-\s*\n\s*/- /}' {} ; \
" \;

# Using .bak then deleting so that the sed works on both mac and gnu sed
find ./doc/seald-sdk-android -type f -name "*.md.bak" -exec rm -f {} \;

echo "'clean-doc.sh' done."
