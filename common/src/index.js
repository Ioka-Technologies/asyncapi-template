/**
 * AsyncAPI Common Template Utilities
 *
 * This package provides shared utilities for AsyncAPI template generation,
 * reducing code duplication across multiple templates.
 */

// String utilities
import {
    toRustIdentifier,
    toRustTypeName,
    toRustFieldName,
    toRustEnumVariant,
    toRustEnumVariantWithSerde,
    toKebabCase,
    toPascalCase,
    toSnakeCase,
    toCamelCase
} from './string-utils.js';

// Message utilities
import {
    getMessageTypeName,
    getMessageRustTypeName,
    getPayloadRustTypeName,
    getMessageTypeScriptTypeName,
    getPayloadTypeScriptTypeName,
    messageHasPayload,
    getMessageContentType
} from './message-utils.js';

// Channel utilities
import {
    getNatsSubject,
    getChannelAddress,
    isDynamicChannel,
    extractChannelVariables,
    extractChannelParameters,
    getChannelParameters,
    resolveChannelAddress,
    channelHasParameters,
    generateChannelParameterArgs,
    generateChannelFormatting,
    generateTypeScriptChannelParameterArgs,
    generateTypeScriptChannelFormatting,
    extractServerNameFromRef,
    analyzeChannelServerMappings,
    isChannelAllowedOnServer
} from './channel-utils.js';

// Security utilities
import {
    analyzeOperationSecurity,
    operationHasSecurity,
    operationRequiresAuth,
    hasSecuritySchemes,
    getSecuritySchemeType,
    getSecuritySchemeName,
    getSecuritySchemeLocation,
    extractOperationSecurityMap,
    getAllSecuritySchemes,
    isSecuritySchemeType,
    getDefaultPort,
    validateChannelServerReferences
} from './security-utils.js';

// Template utilities
import {
    isTemplateVariable,
    extractAsyncApiInfo,
    resolveTemplateParameters,
    generatePackageJson,
    generateReadmeContent,
    validateTemplateParameters,
    generateTypeScriptConfig,
    generateEslintConfig,
    formatGenerationDate,
    generateFileHeader
} from './template-utils.js';

// Operation utilities
import {
    getOperationName,
    getOperationAction,
    getOperationChannel,
    getOperationMessages,
    isOperationSend,
    isOperationReceive,
    getOperationRustFunctionName,
    getOperationTypeScriptMethodName,
    getOperationDescription,
    getOperationSummary,
    extractAllOperations,
    groupOperationsByAction,
    getOperationTraits,
    operationHasTraits,
    getOperationTags,
    generateOperationHandlerName
} from './operation-utils.js';

// Model generation utilities
import { generateRustModels } from './models-rust.js';
import { generateMessageEnvelope } from './envelope-rust.js';
import { generateTypeScriptModels } from './models-ts.js';

// Schema utilities
import {
    getSourcePath,
    parseRef,
    loadExternalSchemas,
    buildSchemaRegistry,
    resolveRef,
    findSchemaNameById
} from './schema-utils.js';

// Re-export all utilities
export {
    // String utilities
    toRustIdentifier,
    toRustTypeName,
    toRustFieldName,
    toRustEnumVariant,
    toRustEnumVariantWithSerde,
    toKebabCase,
    toPascalCase,
    toSnakeCase,
    toCamelCase,
    // Message utilities
    getMessageTypeName,
    getMessageRustTypeName,
    getPayloadRustTypeName,
    getMessageTypeScriptTypeName,
    getPayloadTypeScriptTypeName,
    messageHasPayload,
    getMessageContentType,
    // Channel utilities
    getNatsSubject,
    getChannelAddress,
    isDynamicChannel,
    extractChannelVariables,
    extractChannelParameters,
    getChannelParameters,
    resolveChannelAddress,
    channelHasParameters,
    generateChannelParameterArgs,
    generateChannelFormatting,
    generateTypeScriptChannelParameterArgs,
    generateTypeScriptChannelFormatting,
    extractServerNameFromRef,
    analyzeChannelServerMappings,
    isChannelAllowedOnServer,
    // Security utilities
    analyzeOperationSecurity,
    operationHasSecurity,
    operationRequiresAuth,
    hasSecuritySchemes,
    getSecuritySchemeType,
    getSecuritySchemeName,
    getSecuritySchemeLocation,
    extractOperationSecurityMap,
    getAllSecuritySchemes,
    isSecuritySchemeType,
    getDefaultPort,
    validateChannelServerReferences,
    // Template utilities
    isTemplateVariable,
    extractAsyncApiInfo,
    resolveTemplateParameters,
    generatePackageJson,
    generateReadmeContent,
    validateTemplateParameters,
    generateTypeScriptConfig,
    generateEslintConfig,
    formatGenerationDate,
    generateFileHeader,
    // Operation utilities
    getOperationName,
    getOperationAction,
    getOperationChannel,
    getOperationMessages,
    isOperationSend,
    isOperationReceive,
    getOperationRustFunctionName,
    getOperationTypeScriptMethodName,
    getOperationDescription,
    getOperationSummary,
    extractAllOperations,
    groupOperationsByAction,
    getOperationTraits,
    operationHasTraits,
    getOperationTags,
    generateOperationHandlerName,
    // Model generation utilities
    generateRustModels,
    generateMessageEnvelope,
    generateTypeScriptModels,
    // Schema utilities
    getSourcePath,
    parseRef,
    loadExternalSchemas,
    buildSchemaRegistry,
    resolveRef,
    findSchemaNameById
};

// Version information
export const VERSION = '1.0.0';

// Convenience function to get all utilities in one object
export function getAllUtilities() {
    return {
        string: {
            toRustIdentifier,
            toRustTypeName,
            toRustFieldName,
            toRustEnumVariant,
            toRustEnumVariantWithSerde,
            toKebabCase,
            toPascalCase,
            toSnakeCase,
            toCamelCase
        },
        message: {
            getMessageTypeName,
            getMessageRustTypeName,
            getPayloadRustTypeName,
            getMessageTypeScriptTypeName,
            getPayloadTypeScriptTypeName,
            messageHasPayload,
            getMessageContentType
        },
        channel: {
            getNatsSubject,
            getChannelAddress,
            isDynamicChannel,
            extractChannelVariables,
            extractChannelParameters,
            getChannelParameters,
            resolveChannelAddress,
            channelHasParameters,
            generateChannelParameterArgs,
            generateChannelFormatting,
            generateTypeScriptChannelParameterArgs,
            generateTypeScriptChannelFormatting,
            extractServerNameFromRef,
            analyzeChannelServerMappings,
            isChannelAllowedOnServer
        },
        security: {
            analyzeOperationSecurity,
            operationHasSecurity,
            operationRequiresAuth,
            hasSecuritySchemes,
            getSecuritySchemeType,
            getSecuritySchemeName,
            getSecuritySchemeLocation,
            extractOperationSecurityMap,
            getAllSecuritySchemes,
            isSecuritySchemeType,
            getDefaultPort,
            validateChannelServerReferences
        },
        template: {
            isTemplateVariable,
            extractAsyncApiInfo,
            resolveTemplateParameters,
            generatePackageJson,
            generateReadmeContent,
            validateTemplateParameters,
            generateTypeScriptConfig,
            generateEslintConfig,
            formatGenerationDate,
            generateFileHeader
        },
        operation: {
            getOperationName,
            getOperationAction,
            getOperationChannel,
            getOperationMessages,
            isOperationSend,
            isOperationReceive,
            getOperationRustFunctionName,
            getOperationTypeScriptMethodName,
            getOperationDescription,
            getOperationSummary,
            extractAllOperations,
            groupOperationsByAction,
            getOperationTraits,
            operationHasTraits,
            getOperationTags,
            generateOperationHandlerName
        },
        models: {
            generateRustModels,
            generateMessageEnvelope,
            generateTypeScriptModels
        }
    };
}
