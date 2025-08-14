export default {
    env: {
        browser: true,
        es2021: true,
        node: true,
    },
    extends: [
        'eslint:recommended',
    ],
    parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
        ecmaFeatures: {
            jsx: true,
        },
    },
    rules: {
        'indent': ['error', 4],
        'linebreak-style': ['error', 'unix'],
        'quotes': ['error', 'single'],
        'semi': ['error', 'always'],
        'no-unused-vars': ['error', { 'argsIgnorePattern': '^_' }],
        'no-console': 'warn',
        'prefer-const': 'error',
        'no-var': 'error',
    },
    overrides: [
        {
            files: ['**/template/**/*.js'],
            rules: {
                'no-console': 'off', // Allow console in template files for debugging
                'indent': 'off', // Disable indent rule for template files - let auto-formatter handle it
            },
        },
    ],
    ignorePatterns: ['**/__transpiled/**'],
};
