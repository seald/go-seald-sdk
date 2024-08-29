#!/bin/bash -e

# This is a script that merges two AAR files into a single one. It combines the classes of both.
# For any file that is present in both inputs, the one in INPUT1 will be in the output AAR.

# Initialize variables to store the arguments
INPUT1=""
INPUT2=""
OUTPUT=""

# Loop through all the arguments
while [ "$#" -gt 0 ]; do
  case "$1" in
    --input1)
      INPUT1="$2"
      shift 2
      ;;
    --input2)
      INPUT2="$2"
      shift 2
      ;;
    --output)
      OUTPUT="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

echo "DEBUG: ${INPUT1} ${INPUT2} ${OUTPUT}"

# Check if any of the required arguments are missing
if [ -z "${INPUT1}" ] || [ -z "${INPUT2}" ] || [ -z "${OUTPUT}" ]; then
  echo "Error: Missing one or more required arguments."
  echo "Usage: $0 --input1 VALUE1 --input2 VALUE2 --output VALUE3"
  exit 1
fi

ABSOLUTE_OUTPUT=$(realpath "${OUTPUT}")
TEMP_DIR=$(mktemp -d)

mkdir "${TEMP_DIR}/output"

echo "Unzipping first AAR..."
unzip -q "${INPUT1}" -d "${TEMP_DIR}/input1"
echo "Unzipping first AAR's classes..."
unzip -q "${TEMP_DIR}/input1/classes.jar" -d "${TEMP_DIR}/input1/classes"

echo "Unzipping second AAR..."
unzip -q "${INPUT2}" -d "${TEMP_DIR}/input2"
echo "Unzipping second AAR's classes..."
unzip -q "${TEMP_DIR}/input2/classes.jar" -d "${TEMP_DIR}/input2/classes"

echo "Combining AARs..."
cp -r "${TEMP_DIR}"/input2/* "${TEMP_DIR}/output/"
cp -r "${TEMP_DIR}"/input1/* "${TEMP_DIR}/output/"

echo "Combining classes..."
jar -cf "${TEMP_DIR}/output/classes.jar" -C "${TEMP_DIR}/output/classes/" .

echo "Creating output AAR..."
rm -f "${ABSOLUTE_OUTPUT}"
cd "${TEMP_DIR}/output/"
zip -q -r "${ABSOLUTE_OUTPUT}" ./* -x "./classes/*"

rm -rf "${TEMP_DIR}"

echo "All done!"
