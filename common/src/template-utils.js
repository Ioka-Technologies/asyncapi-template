/**
 * Template parameter utilities for AsyncAPI template generation
 *
 * This module provides functions for handling template parameters and
 * common template operations across different AsyncAPI templates.
 */

import { toKebabCase, toPascalCase } from './string-utils.js';

/**
 * Checks if a parameter contains unresolved template variables
 *
 * @param {string} value - Parameter value to check
 * @returns {boolean} True if the value contains template variables
 */
export function isTemplateVariable(value) {
    return typeof value === 'string' && value.includes('{{') && value.includes('}}');
}

/**
 * Extracts information from AsyncAPI specification with fallbacks
 *
 * @param {object} asyncapi - AsyncAPI specification object
 * @returns {object} Object with title, version, and description
 */
export function extractAsyncApiInfo(asyncapi) {
    let title, version, description;

    try {
        const info = asyncapi.info();
        title = info.title();
        version = info.version();
        description = info.description();
    } catch (error) {
        title = 'UnknownAPI';
        version = '1.0.0';
        description = 'Generated AsyncAPI client';
    }

    return { title, version, description };
}

/**
 * Resolves template parameters with fallbacks based on AsyncAPI info
 *
 * @param {object} params - Template parameters
 * @param {object} asyncApiInfo - AsyncAPI info object from extractAsyncApiInfo
 * @returns {object} Resolved parameters
 */
export function resolveTemplateParameters(params, asyncApiInfo) {
    const { title, version } = asyncApiInfo;

    // Resolve parameters, falling back to extracted values if parameters contain template variables
    const clientName = (params.clientName && !isTemplateVariable(params.clientName))
        ? params.clientName
        : `${toPascalCase(title)}Client`;

    const packageName = (params.packageName && !isTemplateVariable(params.packageName))
        ? params.packageName
        : `${toKebabCase(title)}-client`;

    const packageVersion = (params.packageVersion && !isTemplateVariable(params.packageVersion))
        ? params.packageVersion
        : version;

    const license = (params.license && !isTemplateVariable(params.license))
        ? params.license
        : 'Apache-2.0';

    const author = (params.author && !isTemplateVariable(params.author))
        ? params.author
        : 'AsyncAPI Generator';

    return {
        clientName,
        packageName,
        packageVersion,
        license,
        author
    };
}

/**
 * Generates package.json content for Node.js templates
 *
 * @param {object} resolvedParams - Resolved template parameters
 * @param {object} asyncApiInfo - AsyncAPI info object
 * @param {object} options - Additional options for package.json generation
 * @returns {object} Package.json object
 */
export function generatePackageJson(resolvedParams, asyncApiInfo, options = {}) {
    const { title, description } = asyncApiInfo;
    const {
        packageName,
        packageVersion,
        license,
        author
    } = resolvedParams;

    const basePackage = {
        name: packageName,
        version: packageVersion,
        description: `${description || title} - AsyncAPI Client`,
        author: author,
        license: license,
        keywords: [
            'asyncapi',
            'client',
            title.toLowerCase().replace(/[^a-z0-9]/g, '-'),
            ...(options.additionalKeywords || [])
        ]
    };

    // Merge with additional options
    return {
        ...basePackage,
        ...options.additionalFields
    };
}

/**
 * Generates README.md content for templates
 *
 * @param {object} resolvedParams - Resolved template parameters
 * @param {object} asyncApiInfo - AsyncAPI info object
 * @param {object} asyncapi - AsyncAPI specification object
 * @param {object} options - Additional options for README generation
 * @returns {string} README.md content
 */
export function generateReadmeContent(resolvedParams, asyncApiInfo, asyncapi, options = {}) {
    const { title, description } = asyncApiInfo;
    const { packageName, packageVersion, license } = resolvedParams;

    const sections = {
        title: `# ${title}`,
        description: description || 'Generated AsyncAPI client',
        overview: options.overview || 'This client provides type-safe access to your AsyncAPI service.',
        installation: options.installation || `\`\`\`bash\nnpm install ${packageName}\n\`\`\``,
        usage: options.usage || '// Usage examples will be added here',
        metadata: `## Generated from AsyncAPI

- **AsyncAPI Version**: ${asyncapi.version()}
- **Generated**: ${new Date().toISOString()}
- **Title**: ${title}
- **Version**: ${packageVersion}`,
        license: `## License

${license}`
    };

    // Allow overriding sections
    const finalSections = { ...sections, ...options.sections };

    return Object.values(finalSections).join('\n\n');
}

/**
 * Validates template parameters
 *
 * @param {object} params - Template parameters to validate
 * @param {Array<string>} requiredParams - List of required parameter names
 * @returns {object} Validation result with errors if any
 */
export function validateTemplateParameters(params, requiredParams = []) {
    const result = {
        valid: true,
        errors: [],
        warnings: []
    };

    // Check required parameters
    for (const paramName of requiredParams) {
        if (!params[paramName] || isTemplateVariable(params[paramName])) {
            result.valid = false;
            result.errors.push(`Required parameter '${paramName}' is missing or contains unresolved template variables`);
        }
    }

    // Check for common issues
    if (params.packageName && !/^[a-z0-9-]+$/.test(params.packageName)) {
        result.warnings.push('Package name should only contain lowercase letters, numbers, and hyphens');
    }

    if (params.packageVersion && !/^\d+\.\d+\.\d+/.test(params.packageVersion)) {
        result.warnings.push('Package version should follow semantic versioning (e.g., 1.0.0)');
    }

    return result;
}

/**
 * Generates TypeScript configuration for TypeScript templates
 *
 * @param {object} options - TypeScript configuration options
 * @returns {object} TypeScript configuration object
 */
export function generateTypeScriptConfig(options = {}) {
    const defaultConfig = {
        compilerOptions: {
            target: 'ES2020',
            module: 'ES2020',
            lib: ['ES2020', 'DOM'],
            outDir: './dist',
            rootDir: './src',
            strict: true,
            esModuleInterop: true,
            skipLibCheck: true,
            forceConsistentCasingInFileNames: true,
            declaration: true,
            declarationMap: true,
            sourceMap: true,
            moduleResolution: 'node',
            allowSyntheticDefaultImports: true,
            experimentalDecorators: true,
            emitDecoratorMetadata: true,
            resolveJsonModule: true,
            typeRoots: ['node_modules/@types']
        },
        include: [
            'src/**/*'
        ],
        exclude: [
            'node_modules',
            'dist',
            '**/*.test.ts',
            '**/*.spec.ts'
        ]
    };

    // Merge with custom options
    return {
        ...defaultConfig,
        compilerOptions: {
            ...defaultConfig.compilerOptions,
            ...options.compilerOptions
        },
        include: options.include || defaultConfig.include,
        exclude: options.exclude || defaultConfig.exclude
    };
}

/**
 * Generates ESLint configuration for JavaScript/TypeScript templates
 *
 * @param {object} options - ESLint configuration options
 * @returns {object} ESLint configuration object
 */
export function generateEslintConfig(options = {}) {
    const isTypeScript = options.typescript || false;

    const baseConfig = {
        env: {
            node: true,
            es2021: true
        },
        extends: [
            'eslint:recommended'
        ],
        parserOptions: {
            ecmaVersion: 12,
            sourceType: 'module'
        },
        rules: {
            'indent': ['error', 4],
            'linebreak-style': ['error', 'unix'],
            'quotes': ['error', 'single'],
            'semi': ['error', 'always']
        }
    };

    if (isTypeScript) {
        baseConfig.extends.push('@typescript-eslint/recommended');
        baseConfig.parser = '@typescript-eslint/parser';
        baseConfig.plugins = ['@typescript-eslint'];
    }

    // Merge with custom options
    return {
        ...baseConfig,
        ...options.additionalConfig
    };
}

/**
 * Formats a date for use in generated files
 *
 * @param {Date} date - Date to format (defaults to current date)
 * @returns {string} Formatted date string
 */
export function formatGenerationDate(date = new Date()) {
    return date.toISOString();
}

/**
 * Generates a comment header for generated files
 *
 * @param {object} options - Header options
 * @returns {string} Comment header
 */
export function generateFileHeader(options = {}) {
    const {
        title = 'Generated AsyncAPI File',
        description = 'This file was automatically generated from an AsyncAPI specification.',
        generator = 'AsyncAPI Generator',
        date = new Date(),
        warning = 'Do not modify this file directly.'
    } = options;

    return `/**
 * ${title}
 *
 * ${description}
 *
 * Generated by: ${generator}
 * Generated on: ${formatGenerationDate(date)}
 *
 * WARNING: ${warning}
 */`;
}
