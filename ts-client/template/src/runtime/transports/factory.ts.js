/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

module.exports = function ({ asyncapi, params }) {
    const transports = (params.transports || 'websocket,http').split(',').map(t => t.trim());

    let imports = `import { Transport, TransportConfig } from '../types';\n`;
    let cases = '';

    if (transports.includes('websocket')) {
        imports += `import { WebSocketTransport } from './websocket';\n`;
        cases += `            case 'websocket': return new WebSocketTransport(config);\n`;
    }

    if (transports.includes('http')) {
        imports += `import { HttpTransport } from './http';\n`;
        cases += `            case 'http': return new HttpTransport(config);\n`;
    }

    return (
        <File name="factory.ts">
            {`${imports}
export class TransportFactory {
    static create(config: TransportConfig): Transport {
        switch (config.type) {
${cases}            default:
                throw new Error(\`Unsupported transport type: \${config.type}\`);
        }
    }
}`}
        </File>
    );
}
