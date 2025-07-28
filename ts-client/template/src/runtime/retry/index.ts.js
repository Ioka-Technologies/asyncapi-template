/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

module.exports = function ({ asyncapi, params }) {
    return (
        <File name="index.ts">
            {`// Retry types and interfaces
export * from './types';

// Retry presets
export * from './presets';

// Retry manager
export * from './manager';
`}
        </File>
    );
};
