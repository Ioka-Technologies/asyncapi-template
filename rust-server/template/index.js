/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

// Import all template components
import CargoToml from './Cargo.toml.js';
import ReadmeMd from './README.md.js';
import UsageMd from './USAGE.md.js';
import LibRs from './src/lib.rs.js';
import ConfigRs from './src/config.rs.js';
import ErrorsRs from './src/errors.rs.js';
import ModelsRs from './src/models.rs.js';
import HandlersRs from './src/handlers.rs.js';
import ContextRs from './src/context.rs.js';
// Import server module components
import ServerMod from './src/server/mod.rs.js';
import ServerBuilder from './src/server/builder.rs.js';
import MiddlewareRs from './src/middleware.rs.js';
import RecoveryRs from './src/recovery.rs.js';

// Import auth module components
import AuthMod from './src/auth/mod.rs.js';
import AuthConfig from './src/auth/config.rs.js';
import AuthJwt from './src/auth/jwt.rs.js';
import AuthMiddleware from './src/auth/middleware.rs.js';
import AuthRbac from './src/auth/rbac.rs.js';

// Import transport components
import TransportMod from './src/transport/mod.rs.js';
import TransportFactory from './src/transport/factory.rs.js';
import MqttTransport from './src/transport/mqtt.rs.js';
import KafkaTransport from './src/transport/kafka.rs.js';
import AmqpTransport from './src/transport/amqp.rs.js';
import WebSocketTransport from './src/transport/websocket.rs.js';
import HttpTransport from './src/transport/http.rs.js';

export default function ({ asyncapi, params }) {
    return [
        <CargoToml asyncapi={asyncapi} params={params} />,
        <ReadmeMd asyncapi={asyncapi} params={params} />,
        <UsageMd asyncapi={asyncapi} params={params} />,
        <LibRs asyncapi={asyncapi} params={params} />,
        <ConfigRs asyncapi={asyncapi} params={params} />,
        <ErrorsRs asyncapi={asyncapi} params={params} />,
        <ModelsRs asyncapi={asyncapi} params={params} />,
        <HandlersRs asyncapi={asyncapi} params={params} />,
        <ContextRs asyncapi={asyncapi} params={params} />,
        <ServerMod asyncapi={asyncapi} params={params} />,
        <ServerBuilder asyncapi={asyncapi} params={params} />,
        <MiddlewareRs asyncapi={asyncapi} params={params} />,
        <RecoveryRs asyncapi={asyncapi} params={params} />,
        <AuthMod asyncapi={asyncapi} params={params} />,
        <AuthConfig asyncapi={asyncapi} params={params} />,
        <AuthJwt asyncapi={asyncapi} params={params} />,
        <AuthMiddleware asyncapi={asyncapi} params={params} />,
        <AuthRbac asyncapi={asyncapi} params={params} />,
        <TransportMod asyncapi={asyncapi} params={params} />,
        <TransportFactory asyncapi={asyncapi} params={params} />,
        <MqttTransport asyncapi={asyncapi} params={params} />,
        <KafkaTransport asyncapi={asyncapi} params={params} />,
        <AmqpTransport asyncapi={asyncapi} params={params} />,
        <WebSocketTransport asyncapi={asyncapi} params={params} />,
        <HttpTransport asyncapi={asyncapi} params={params} />
    ];
}
