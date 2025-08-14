/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';
import { generateTypeScriptModels } from '../../../common/src/index.js';

export default function ({ asyncapi, params }) {
    // Generate models using the common helper
    const models = generateTypeScriptModels(asyncapi, {
        includeMessageTypes: true // TypeScript client includes message type constants
    });

    return (
        <File name="models.ts">
            {`// Generated TypeScript models from AsyncAPI specification

${models.generateComponentSchemas()}
${models.generateMessageSchemas()}
${models.generateMessageTypes()}
`}
        </File>
    );
}
