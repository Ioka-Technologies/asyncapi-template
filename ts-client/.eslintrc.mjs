import rootConfig from '../.eslintrc.mjs';

export default {
    ...rootConfig,
    root: true,
    ignorePatterns: [
        ...rootConfig.ignorePatterns,
        '__transpiled/**',
        'dist/**',
        'test-output*/**'
    ]
};
