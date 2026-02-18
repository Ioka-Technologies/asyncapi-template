export class TransportError extends Error {
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
}