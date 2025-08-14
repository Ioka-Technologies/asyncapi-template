/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function ({ asyncapi, params }) {
    return (
        <File name="index.ts">
            {`export * from './client';
export * from './models';
export * from './runtime/types';
export * from './runtime/errors';`}
        </File>
    );
}
