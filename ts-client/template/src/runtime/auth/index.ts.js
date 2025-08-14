/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function ({ asyncapi, params }) {
    return (
        <File name="index.ts">
            {`// Auth types and interfaces
export * from './types';

// Auth header utilities
export * from './headers';
`}
        </File>
    );
}
