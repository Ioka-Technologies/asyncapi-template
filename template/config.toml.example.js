import { File } from '@asyncapi/generator-react-sdk';

export default function configExampleFile({ asyncapi, params }) {
    const server = asyncapi.allServers().get(params.server);
    const protocol = server.protocol();
    const serverUrl = server.url();

    return (
        <File name="config.toml.example">
            {`# Example configuration file for AsyncAPI Rust client
# Copy this file to config.toml and modify as needed

[server]
url = "${serverUrl}"
timeout = 30
max_retries = 3

${protocol === 'mqtt' || protocol === 'mqtts' ? `[mqtt]
client_id = "asyncapi-client-example"
keep_alive = 60
clean_session = true
qos = 1
# username = "your-username"
# password = "your-password"` : ''}

${protocol === 'kafka' || protocol === 'kafka-secure' ? `[kafka]
group_id = "asyncapi-group"
auto_offset_reset = "earliest"
enable_auto_commit = true
session_timeout = 30000
# security_protocol = "SASL_SSL"
# sasl_mechanism = "PLAIN"
# sasl_username = "your-username"
# sasl_password = "your-password"` : ''}

${protocol === 'amqp' || protocol === 'amqps' ? `[amqp]
vhost = "/"
connection_timeout = 30
heartbeat = 60
# username = "your-username"
# password = "your-password"` : ''}

${protocol === 'ws' || protocol === 'wss' ? `[websocket]
max_message_size = 67108864  # 64MB
connection_timeout = 30
ping_interval = 30` : ''}

${protocol === 'nats' ? `[nats]
max_reconnects = 10
reconnect_delay = 2000
# name = "asyncapi-client"
# username = "your-username"
# password = "your-password"
# token = "your-token"` : ''}

${protocol === 'redis' ? `[redis]
db = 0
connection_timeout = 30
response_timeout = 30
# username = "your-username"
# password = "your-password"` : ''}

${protocol === 'http' || protocol === 'https' ? `[http]
timeout = 30
user_agent = "AsyncAPI-Rust-Client/1.0.0"
max_redirects = 10

# [http.default_headers]
# "Authorization" = "Bearer your-token"
# "Content-Type" = "application/json"` : ''}
`}
        </File>
    );
}
