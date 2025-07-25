/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

module.exports = function ({ asyncapi, params }) {
    return (
        <File name="errors.ts">
            {`export class TransportError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'TransportError';
    }
}

export class ConnectionError extends TransportError {
    constructor(message: string) {
        super(message);
        this.name = 'ConnectionError';
    }
}

export class TimeoutError extends TransportError {
    constructor(message: string) {
        super(message);
        this.name = 'TimeoutError';
    }
}`}
        </File>
    );
}
