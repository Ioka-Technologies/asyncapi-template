import { Transport, TransportConfig } from '../types';
import { WebSocketTransport } from './websocket';
import { HttpTransport } from './http';

export class TransportFactory {
    static create(config: TransportConfig): Transport {
        switch (config.type) {
            case 'websocket': return new WebSocketTransport(config);
            case 'http': return new HttpTransport(config);
            default:
                throw new Error(`Unsupported transport type: ${config.type}`);
        }
    }
}