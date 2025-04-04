#!/bin/bash
set -e

# Directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Root directory of the project
PROJECT_ROOT="$SCRIPT_DIR/.."
# Example code path
EXAMPLE_PATH="$PROJECT_ROOT/examples/test.c"
# Include directory
INCLUDE_DIR="$PROJECT_ROOT/include"

# Build the library in debug mode for better Valgrind results
echo "Building library in debug mode..."
cd "$PROJECT_ROOT"
cargo build

# Check if valgrind is installed
if command -v valgrind &> /dev/null; then
    VALGRIND_AVAILABLE=true
    echo "Valgrind found, will run memory tests."
else
    VALGRIND_AVAILABLE=false
    echo "Valgrind not found, skipping memory tests."
fi

# Determine platform-specific settings
OS="$(uname)"
if [ "$OS" == "Darwin" ]; then
    # macOS
    LIB_PATH="$PROJECT_ROOT/target/debug"
    LIB_ENV="DYLD_LIBRARY_PATH"
    LIB_NAME="libhessra.dylib"
elif [ "$OS" == "Linux" ]; then
    # Linux
    LIB_PATH="$PROJECT_ROOT/target/debug"
    LIB_ENV="LD_LIBRARY_PATH"
    LIB_NAME="libhessra.so"
else
    # Windows or other
    echo "Unsupported platform: $OS"
    exit 1
fi

# Build the test executable
echo "Building test executable..."
gcc -o "$PROJECT_ROOT/test_debug" "$EXAMPLE_PATH" -L"$LIB_PATH" -lhessra -I"$INCLUDE_DIR"

# Run the functional test
echo "Running functional test..."
$LIB_ENV="$LIB_PATH" "$PROJECT_ROOT/test_debug"
FUNCTIONAL_TEST_RESULT=$?

# Run the memory tests with Valgrind if available
if [ "$VALGRIND_AVAILABLE" = true ]; then
    echo "Running memory tests with Valgrind..."
    valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
        --log-file="$PROJECT_ROOT/valgrind_results.txt" \
        $LIB_ENV="$LIB_PATH" "$PROJECT_ROOT/test_debug"
    
    # Check if Valgrind found any errors
    if grep -q "ERROR SUMMARY: 0 errors" "$PROJECT_ROOT/valgrind_results.txt"; then
        echo "Valgrind found no memory errors."
        VALGRIND_TEST_RESULT=0
    else
        echo "Valgrind found memory errors. See valgrind_results.txt for details."
        cat "$PROJECT_ROOT/valgrind_results.txt"
        VALGRIND_TEST_RESULT=1
    fi
else
    # Skip Valgrind if not available
    VALGRIND_TEST_RESULT=0
fi

# Clean up
echo "Cleaning up..."
rm -f "$PROJECT_ROOT/test_debug"

# Report results
echo "Test results summary:"
echo "- Functional test: $([ $FUNCTIONAL_TEST_RESULT -eq 0 ] && echo 'PASSED' || echo 'FAILED')"
if [ "$VALGRIND_AVAILABLE" = true ]; then
    echo "- Memory test: $([ $VALGRIND_TEST_RESULT -eq 0 ] && echo 'PASSED' || echo 'FAILED')"
fi

# Return overall success/failure
if [ $FUNCTIONAL_TEST_RESULT -eq 0 ] && [ $VALGRIND_TEST_RESULT -eq 0 ]; then
    echo "All tests PASSED!"
    exit 0
else
    echo "Some tests FAILED!"
    exit 1
fi 