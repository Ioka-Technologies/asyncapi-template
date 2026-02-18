/**
 * Shared schema utilities for AsyncAPI templates
 * Handles external file references and schema registry building
 */

import fs from 'fs';
import path from 'path';
import yaml from 'js-yaml';

/**
 * Get the source file path from the asyncapi object
 * @param {Object} asyncapi - AsyncAPI document
 * @returns {string|null} The source file path or null if not available
 */
export function getSourcePath(asyncapi) {
    try {
        if (asyncapi._meta && asyncapi._meta.asyncapi && asyncapi._meta.asyncapi.source) {
            return asyncapi._meta.asyncapi.source;
        }
    } catch (e) {
        // Ignore
    }
    return null;
}

/**
 * Parse a YAML file and return its contents
 * @param {string} filePath - Path to the YAML file
 * @returns {Object|null} Parsed YAML content or null on error
 */
function parseYamlFile(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        return yaml.load(content);
    } catch (e) {
        console.warn(`Failed to parse YAML file ${filePath}:`, e.message);
        return null;
    }
}

/**
 * Extract schema name from a $ref string
 * Handles both local refs (#/components/schemas/Name) and external refs (file.yaml#/Name)
 * @param {string} ref - The $ref string
 * @returns {{ filePath: string|null, schemaName: string }} Parsed ref info
 */
export function parseRef(ref) {
    if (!ref || typeof ref !== 'string') {
        return { filePath: null, schemaName: '' };
    }

    const hashIndex = ref.indexOf('#');
    if (hashIndex === -1) {
        // No hash, treat entire string as file path
        return { filePath: ref, schemaName: '' };
    }

    const filePath = hashIndex > 0 ? ref.substring(0, hashIndex) : null;
    const fragment = ref.substring(hashIndex + 1);

    // Extract schema name from fragment (e.g., /components/schemas/Name or /Name)
    const schemaName = fragment.split('/').pop() || '';

    return { filePath, schemaName };
}

/**
 * Load schemas from an external YAML file
 * @param {string} externalFilePath - Path to the external file (relative to base)
 * @param {string} basePath - Base directory path
 * @returns {Map<string, Object>} Map of schema name to schema definition
 */
export function loadExternalSchemas(externalFilePath, basePath) {
    const schemas = new Map();

    try {
        const fullPath = path.resolve(basePath, externalFilePath);
        const content = parseYamlFile(fullPath);

        if (content && typeof content === 'object') {
            // External schema files typically have schemas at the top level
            // e.g., { DeviceConfiguration: { type: 'object', ... }, BaseConfig: { ... } }
            Object.entries(content).forEach(([name, schema]) => {
                if (schema && typeof schema === 'object' && !name.startsWith('$')) {
                    schemas.set(name, schema);
                }
            });
        }
    } catch (e) {
        console.warn(`Failed to load external schemas from ${externalFilePath}:`, e.message);
    }

    return schemas;
}

/**
 * Recursively find all external file references in a schema
 * @param {Object} schema - Schema to scan
 * @param {Set<string>} refs - Set to collect refs into
 */
function findExternalRefs(schema, refs) {
    if (!schema || typeof schema !== 'object') return;

    if (schema.$ref && typeof schema.$ref === 'string') {
        const { filePath } = parseRef(schema.$ref);
        if (filePath) {
            refs.add(filePath);
        }
    }

    // Recursively scan all properties
    for (const value of Object.values(schema)) {
        if (Array.isArray(value)) {
            value.forEach(item => findExternalRefs(item, refs));
        } else if (value && typeof value === 'object') {
            findExternalRefs(value, refs);
        }
    }
}

/**
 * Build a comprehensive schema registry from the AsyncAPI document
 * Includes schemas from components/schemas and external files
 * Recursively loads external files that reference other external files
 *
 * @param {Object} asyncapi - AsyncAPI document
 * @returns {Map<string, Object>} Map of schema name to schema definition
 */
export function buildSchemaRegistry(asyncapi) {
    const registry = new Map();
    const sourcePath = getSourcePath(asyncapi);
    const basePath = sourcePath ? path.dirname(sourcePath) : null;

    // Get raw document
    let rawDoc = null;
    try {
        if (asyncapi.json && typeof asyncapi.json === 'function') {
            rawDoc = asyncapi.json();
        } else if (asyncapi._json) {
            rawDoc = asyncapi._json;
        }
    } catch (e) {
        // Ignore
    }

    // 1. Add schemas from components/schemas
    if (rawDoc && rawDoc.components && rawDoc.components.schemas) {
        Object.entries(rawDoc.components.schemas).forEach(([name, schema]) => {
            if (name && typeof name === 'string' && schema && typeof schema === 'object') {
                registry.set(name, schema);
            }
        });
    }

    // 2. Find and load external file references from the ORIGINAL (unparsed) file
    // The parser resolves all $refs, so we need to read the original file to find external refs
    // We need to recursively scan external files for their own external refs
    if (basePath && sourcePath) {
        try {
            const originalContent = parseYamlFile(sourcePath);
            if (originalContent) {
                const processedFiles = new Set();
                const filesToProcess = new Set();

                // Scan the original document for external refs
                findExternalRefs(originalContent, filesToProcess);

                // Process files recursively until no new files are found
                while (filesToProcess.size > 0) {
                    const currentFiles = Array.from(filesToProcess);
                    filesToProcess.clear();

                    for (const externalFile of currentFiles) {
                        if (processedFiles.has(externalFile)) {
                            continue;
                        }
                        processedFiles.add(externalFile);

                        // Load schemas from this external file
                        const externalSchemas = loadExternalSchemas(externalFile, basePath);

                        // Calculate the directory of this external file for resolving relative refs
                        const externalFileDir = path.dirname(externalFile);

                        for (const [name, schema] of externalSchemas) {
                            if (!registry.has(name)) {
                                registry.set(name, schema);
                            }
                            // Scan this schema for more external refs
                            const newRefs = new Set();
                            findExternalRefs(schema, newRefs);
                            // Resolve relative refs from the external file's directory
                            for (const ref of newRefs) {
                                // If the ref is relative (doesn't start with /), resolve it from the external file's directory
                                const resolvedRef = ref.startsWith('/') ? ref : path.join(externalFileDir, ref);
                                filesToProcess.add(resolvedRef);
                            }
                        }

                        // Also scan the entire file content for refs (in case there are refs at the file level)
                        try {
                            const fullPath = path.resolve(basePath, externalFile);
                            const fileContent = parseYamlFile(fullPath);
                            if (fileContent) {
                                const newRefs = new Set();
                                findExternalRefs(fileContent, newRefs);
                                // Resolve relative refs from the external file's directory
                                for (const ref of newRefs) {
                                    const resolvedRef = ref.startsWith('/') ? ref : path.join(externalFileDir, ref);
                                    filesToProcess.add(resolvedRef);
                                }
                            }
                        } catch (e) {
                            // Ignore file read errors
                        }
                    }
                }
            }
        } catch (e) {
            console.warn('Failed to load external schemas:', e.message);
        }
    }

    return registry;
}

/**
 * Resolve a schema reference to its actual schema definition
 * @param {string} ref - The $ref string
 * @param {Map<string, Object>} registry - Schema registry
 * @returns {Object|null} The resolved schema or null
 */
export function resolveRef(ref, registry) {
    const { schemaName } = parseRef(ref);
    if (schemaName && registry.has(schemaName)) {
        return registry.get(schemaName);
    }
    return null;
}

/**
 * Check if a schema ID matches a known schema in the registry
 * Handles anonymous schema IDs like "<anonymous-schema-3>"
 * @param {string} schemaId - The x-parser-schema-id value
 * @param {Map<string, Object>} registry - Schema registry
 * @returns {string|null} The matching schema name or null
 */
export function findSchemaNameById(schemaId, registry) {
    // If it's not an anonymous ID, check if it's directly in the registry
    if (!schemaId.startsWith('<anonymous-schema-')) {
        if (registry.has(schemaId)) {
            return schemaId;
        }
    }

    // For anonymous schemas, we can't reliably match them
    // The caller should use other methods (like checking $ref in raw document)
    return null;
}
