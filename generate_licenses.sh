#!/bin/bash -e

go-licenses report ./mobile_sdk > dependencies_licenses.csv 2> dependencies_licenses_errors

# Flag to indicate if the next lines are paths that should be ignored
ignore_paths=false

# Check that licenses_errors only contains expected errors
while IFS= read -r line || [[ -n "$line" ]]; do
  if [[ $ignore_paths == true ]]; then
    # Check if the line is a path (adjust the condition to match your paths)
    if [[ $line =~ ^/ ]]; then
      # It's a path, so ignore it and continue
      continue
    else
      # No longer a path, reset the flag and handle the line normally
      ignore_paths=false
    fi
  fi

  if [[ -z "$line" ]]; then
    # empty line, nothing to do
    :
  elif [[ "$line" == *"module github.com/seald/go-seald-sdk has empty version, defaults to HEAD. The license URL may be incorrect. Please verify!"* ]]; then
    # this is the main go SDK package itself: nothing special to do, just ignore
    :
  elif [[ "$line" == *"contains non-Go code that can't be inspected for further dependencies"* ]]; then
    # this is expected, can ignore
    # but this message prints extra lines with the paths of the files in question, so let's set the flag to consume them
    ignore_paths=true
  else
    echo "No match found for: $line"
    exit 1
  fi
done < "dependencies_licenses_errors"

download_github_file() {
  # The normal GitHub URL
  local github_url="$1"

  # Validate URL
  if [[ ! "$github_url" =~ ^https://github\.com/[^/]+/[^/]+/blob/[^/]+/.*$ ]]; then
    echo "Invalid GitHub URL: $github_url" >&2
    exit 1
  fi

  # Extract username, repo, commit and filepath from the GitHub URL
  local username=$(echo "$github_url" | awk -F'/' '{print $4}')
  local repo=$(echo "$github_url" | awk -F'/' '{print $5}')
  local git_ref=$(echo "$github_url" | awk -F'/' '{print $7}')
  local filepath=$(echo "$github_url" | cut -d'/' -f8-)

  # Construct the raw GitHub URL
  local raw_url="https://raw.githubusercontent.com/$username/$repo/$git_ref/$filepath"

  # Download the file using curl
  curl --fail -sS "$raw_url"
}

download_google_source_file() {
  local url="$1"

  # Validate the URL format (rudimentary)
  if [[ ! "$url" =~ ^https://cs\.opensource\.google/go/x/[^/]+/\+/[^:]+:[^/]+$ ]]; then
    echo "Invalid GoogleSource URL: $url" >&2
    exit 1
  fi

  # Extract repo, tag, and filepath
  local repo=$(echo "$url" | awk -F'/' '{print $6}' | sed 's/^x\///')
  local git_ref=$(echo "$url" | awk -F'/' '{print $8}' | awk -F':' '{print $1}')
  local filepath="${url##*:}"

  # cs.opensource.google does not expose a raw URL, so let's use the github mirror
  local raw_url="https://raw.githubusercontent.com/golang/$repo/$git_ref/$filepath"

  # Download the file using curl
  curl --fail -sS "$raw_url"
}

echo -e "Seald SDK for mobile ${PACKAGE_VERSION} is made using these Open Source packages:\n" > dependencies_licenses.txt

# Read CSV line by line
while IFS=, read -r package_name license_url license_type; do
  echo "Handling ${package_name}..."
  if [[ "$package_name" == "github.com/seald/go-seald-sdk" ]]; then
    echo "  Main package, ignoring."
  elif [[ "$package_name" == "github.com/seald/go-seald-sdk/"* ]]; then
    echo "  Internal package, ignoring."
  elif [[ "$license_url" == "Unknown" ]]; then
    echo "Unknown license for package $package_name"
    exit 1
  elif [[ "$license_url" == "https://"* ]]; then
    echo -e "==== ${package_name} ====\n" >> dependencies_licenses.txt
    if [[ "$license_url" == "https://github.com/"* ]]; then
      echo "  Downloading license from GitHub..."
      download_github_file $license_url >> dependencies_licenses.txt
      echo -e "\n" >> dependencies_licenses.txt
    elif [[ "$license_url" == "https://cs.opensource.google/go/x/"* ]]; then
      echo "  Downloading license from GoogleSource..."
      download_google_source_file $license_url >> dependencies_licenses.txt
      echo -e "\n" >> dependencies_licenses.txt
    else
      echo "Unknown URL format for package $package_name: $license_url"
      exit 1
    fi
  else
    echo "Invalid license URL for package $package_name: $license_url"
    exit 1
  fi
done < "dependencies_licenses.csv"

# Extra licenses
echo -e "==== kotlin-stdlib-jdk8 ====\n" >> dependencies_licenses.txt
download_github_file https://github.com/JetBrains/kotlin/blob/v1.9.10/license/LICENSE.txt >> dependencies_licenses.txt
echo -e "\n" >> dependencies_licenses.txt

echo -e "==== kotlinx-coroutines-android ====\n" >> dependencies_licenses.txt
download_github_file https://github.com/JetBrains/kotlin/blob/v1.9.10/license/LICENSE.txt >> dependencies_licenses.txt
echo -e "\n" >> dependencies_licenses.txt
