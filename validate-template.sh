#!/bin/bash

# AsyncAPI Rust Template Validation Script
# This script validates the template structure and files

echo "🔍 Validating AsyncAPI Rust Template Structure..."
echo

# Check if all required template files exist
TEMPLATE_FILES=(
    "template/index.js"
    "template/Cargo.toml.js"
    "template/README.md.js"
    "template/.gitignore.js"
    "template/config.toml.example.js"
    "template/src/lib.rs.js"
    "template/src/config.rs.js"
    "template/src/context.rs.js"
    "template/src/error.rs.js"
    "template/src/handlers.rs.js"
    "template/src/middleware.rs.js"
    "template/src/models.rs.js"
    "template/src/router.rs.js"
    "template/src/server.rs.js"
    "template/src/transport.rs.js"
    "template/src/main.rs.js"
    "template/src/client.rs.js"
    "template/src/transport/mod.rs.js"
    "template/src/transport/factory.rs.js"
    "template/src/transport/mqtt.rs.js"
    "template/examples/basic_server.rs.js"
)

HELPER_FILES=(
    "helpers/index.js"
    "helpers/general.js"
    "helpers/rust-helpers.js"
)

TEST_FILES=(
    "test/fixtures/mqtt.yaml"
    "test/fixtures/kafka.yaml"
    "test/fixtures/amqp.yaml"
    "test/generator.test.js"
)

PROJECT_FILES=(
    "package.json"
    "README.md"
    "LICENSE"
    "CONTRIBUTING.md"
)

# Function to check if file exists and is not empty
check_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        if [[ -s "$file" ]]; then
            echo "✅ $file"
            return 0
        else
            echo "⚠️  $file (empty)"
            return 1
        fi
    else
        echo "❌ $file (missing)"
        return 1
    fi
}

# Check template files
echo "📁 Template Files:"
template_errors=0
for file in "${TEMPLATE_FILES[@]}"; do
    if ! check_file "$file"; then
        ((template_errors++))
    fi
done
echo

# Check helper files
echo "🔧 Helper Files:"
helper_errors=0
for file in "${HELPER_FILES[@]}"; do
    if ! check_file "$file"; then
        ((helper_errors++))
    fi
done
echo

# Check test files
echo "🧪 Test Files:"
test_errors=0
for file in "${TEST_FILES[@]}"; do
    if ! check_file "$file"; then
        ((test_errors++))
    fi
done
echo

# Check project files
echo "📋 Project Files:"
project_errors=0
for file in "${PROJECT_FILES[@]}"; do
    if ! check_file "$file"; then
        ((project_errors++))
    fi
done
echo

# Validate package.json structure
echo "📦 Package.json Validation:"
if [[ -f "package.json" ]]; then
    # Check for required fields
    if grep -q '"name"' package.json && \
       grep -q '"version"' package.json && \
       grep -q '"description"' package.json && \
       grep -q '"generator"' package.json; then
        echo "✅ package.json has required fields"
    else
        echo "❌ package.json missing required fields"
        ((project_errors++))
    fi

    # Check for AsyncAPI generator configuration
    if grep -q '"supportedProtocols"' package.json; then
        echo "✅ package.json has supportedProtocols"
    else
        echo "❌ package.json missing supportedProtocols"
        ((project_errors++))
    fi

    # Check for template parameters
    if grep -q '"parameters"' package.json; then
        echo "✅ package.json has template parameters"
    else
        echo "❌ package.json missing template parameters"
        ((project_errors++))
    fi
else
    echo "❌ package.json not found"
    ((project_errors++))
fi
echo

# Validate test fixtures
echo "🎯 Test Fixture Validation:"
fixture_errors=0

for fixture in test/fixtures/*.yaml; do
    if [[ -f "$fixture" ]]; then
        # Check if it's valid YAML (basic check)
        if grep -q "asyncapi:" "$fixture" && \
           grep -q "info:" "$fixture" && \
           grep -q "channels:" "$fixture"; then
            echo "✅ $(basename "$fixture") appears to be valid AsyncAPI spec"
        else
            echo "❌ $(basename "$fixture") missing required AsyncAPI fields"
            ((fixture_errors++))
        fi
    fi
done
echo

# Summary
total_errors=$((template_errors + helper_errors + test_errors + project_errors + fixture_errors))

echo "📊 Validation Summary:"
echo "   Template files: $((${#TEMPLATE_FILES[@]} - template_errors))/${#TEMPLATE_FILES[@]} ✅"
echo "   Helper files: $((${#HELPER_FILES[@]} - helper_errors))/${#HELPER_FILES[@]} ✅"
echo "   Test files: $((${#TEST_FILES[@]} - test_errors))/${#TEST_FILES[@]} ✅"
echo "   Project files: $((${#PROJECT_FILES[@]} - project_errors))/${#PROJECT_FILES[@]} ✅"
echo "   Test fixtures: $((3 - fixture_errors))/3 ✅"
echo

if [[ $total_errors -eq 0 ]]; then
    echo "🎉 All validation checks passed! Template is ready for use."
    exit 0
else
    echo "⚠️  Found $total_errors issues. Please fix them before using the template."
    exit 1
fi
