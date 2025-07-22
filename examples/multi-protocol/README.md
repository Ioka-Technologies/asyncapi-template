# Multi-Protocol Event Processing Service

This example demonstrates how to build a comprehensive event processing service that handles multiple protocols (MQTT, Kafka, WebSocket, and HTTP) in a single Rust application using the AsyncAPI template.

## Overview

This example showcases:
- **Multi-Protocol Architecture**: MQTT, Kafka, WebSocket, and HTTP in one service
- **Event-Driven Design**: Cross-protocol event routing and processing
- **Real-time Communication**: WebSocket for live updates
- **Message Streaming**: Kafka for reliable event streaming
- **IoT Integration**: MQTT for device communication
- **API Integration**: HTTP for external service integration

## Architecture

```
┌─────────────────┐    MQTT     ┌─────────────────────────────────────┐    WebSocket   ┌─────────────────┐
│   IoT Devices   │────────────►│                                     │───────────────►│   Dashboard     │
└─────────────────┘             │                                     │                └─────────────────┘
                                │                                     │
┌─────────────────┐    Kafka    │        Multi-Protocol              │    HTTP        ┌─────────────────┐
│  Microservices  │────────────►│        Event Processor             │◄───────────────│  External APIs  │
└─────────────────┘             │                                     │                └─────────────────┘
                                │                                     │
┌─────────────────┐    HTTP     │  • Event Routing                   │    WebSocket   ┌─────────────────┐
│   Web Clients   │────────────►│  • Protocol Translation            │───────────────►│  Mobile Apps    │
└─────────────────┘             │  • Real-time Processing            │                └─────────────────┘
                                └─────────────────────────────────────┘
```

## Protocol Usage Patterns

### MQTT - IoT Device Communication
- **Purpose**: Lightweight messaging for IoT devices
- **Channels**: `iot/sensors/{sensorId}/data`
- **Use Cases**: Sensor data collection, device telemetry

### Kafka - Event Streaming
- **Purpose**: Reliable, scalable event streaming
- **Channels**: `events.user.created`, `events.order.placed`, `events.payment.processed`
- **Use Cases**: Microservice communication, event sourcing, data pipelines

### WebSocket - Real-time Updates
- **Purpose**: Bidirectional real-time communication
- **Channels**: `notifications/user/{userId}`, `dashboard/metrics`
- **Use Cases**: Live notifications, real-time dashboards, chat systems

### HTTP - API Integration
- **Purpose**: Request/response communication with external services
- **Channels**: `api/webhooks/external`, `api/events/publish`
- **Use Cases**: Webhook handling, REST API endpoints, external integrations

## Generated Code Structure

### Multi-Protocol Server (`src/server.rs`)
```rust
impl Server {
    pub async fn start(&self) -> Result<()> {
        info!("Starting multi-protocol event processor");

        // Start all protocol handlers concurrently
        let mqtt_handle = self.start_mqtt_handler();
        let kafka_handle = self.start_kafka_handler();
        let websocket_handle = self.start_websocket_handler();
        let http_handle = self.start_http_handler();

        // Wait for all handlers to start
        tokio::try_join!(
            mqtt_handle,
            kafka_handle,
            websocket_handle,
            http_handle
        )?;

        info!("All protocol handlers started successfully");
        Ok(())
    }

    async fn start_mqtt_handler(&self) -> Result<()> {
        // MQTT client setup for IoT devices
        let mut mqttoptions = rumqttc::MqttOptions::new(
            "event-processor",
            &self.config.mqtt_config.host,
            self.config.mqtt_config.port
        );

        let (client, mut eventloop) = rumqttc::AsyncClient::new(mqttoptions, 10);
        client.subscribe("iot/sensors/+/data", rumqttc::QoS::AtLeastOnce).await?;

        // Handle MQTT messages
        let handlers = self.handlers.clone();
        tokio::spawn(async move {
            // MQTT event loop implementation
        });

        Ok(())
    }

    async fn start_kafka_handler(&self) -> Result<()> {
        // Kafka consumer setup for event streaming
        let consumer: StreamConsumer = ClientConfig::new()
            .set("group.id", "event-processor")
            .set("bootstrap.servers", &self.config.kafka_config.brokers)
            .create()?;

        consumer.subscribe(&["events.user.created", "events.order.placed"])?;

        // Handle Kafka messages
        let handlers = self.handlers.clone();
        tokio::spawn(async move {
            // Kafka consumer loop implementation
        });

        Ok(())
    }

    async fn start_websocket_handler(&self) -> Result<()> {
        // WebSocket server setup for real-time communication
        let app = Router::new()
            .route("/ws", get(websocket_handler))
            .with_state(self.handlers.clone());

        let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
        axum::serve(listener, app).await?;

        Ok(())
    }

    async fn start_http_handler(&self) -> Result<()> {
        // HTTP API setup for external integrations
        let app = Router::new()
            .route("/api/webhooks/external", post(handle_webhook))
            .route("/api/events/publish", post(handle_event_publish))
            .with_state(self.handlers.clone());

        let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await?;
        axum::serve(listener, app).await?;

        Ok(())
    }
}
```

### Cross-Protocol Event Routing (`src/handlers.rs`)
```rust
impl EventProcessor {
    pub async fn handle_sensor_data(&self, data: SensorDataPayload) -> Result<()> {
        info!("Processing sensor data from {}", data.sensor_id);

        // Process the sensor data
        self.process_sensor_reading(&data).await?;

        // Route to other protocols based on business logic
        if data.type_field == "temperature" && data.value > 80.0 {
            // Send critical alert via WebSocket
            self.send_critical_alert(&data).await?;

            // Publish alert event to Kafka
            self.publish_alert_event(&data).await?;
        }

        // Update real-time dashboard via WebSocket
        self.update_dashboard_metrics(&data).await?;

        Ok(())
    }

    pub async fn handle_user_created(&self, event: UserCreatedPayload) -> Result<()> {
        info!("Processing user creation for {}", event.user_id);

        // Send welcome notification via WebSocket
        let notification = UserNotificationPayload {
            notification_id: Uuid::new_v4(),
            user_id: event.user_id,
            type_field: "success".to_string(),
            title: "Welcome!".to_string(),
            message: "Your account has been created successfully".to_string(),
            data: None,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::days(7)),
        };

        self.send_user_notification(notification).await?;

        // Update user metrics on dashboard
        self.update_user_metrics().await?;

        Ok(())
    }

    pub async fn handle_order_placed(&self, event: OrderPlacedPayload) -> Result<()> {
        info!("Processing order placement {}", event.order_id);

        // Process payment (simulate)
        let payment_result = self.process_payment(&event).await?;

        // Publish payment processed event to Kafka
        let payment_event = PaymentProcessedPayload {
            payment_id: Uuid::new_v4(),
            order_id: event.order_id,
            user_id: event.user_id,
            amount: event.total_amount,
            currency: event.currency,
            method: "credit_card".to_string(),
            status: if payment_result.success { "success" } else { "failed" }.to_string(),
            processed_at: Utc::now(),
            transaction_id: payment_result.transaction_id,
        };

        self.publish_payment_processed(payment_event).await?;

        // Notify user via WebSocket
        let notification = UserNotificationPayload {
            notification_id: Uuid::new_v4(),
            user_id: event.user_id,
            type_field: if payment_result.success { "success" } else { "error" }.to_string(),
            title: "Order Update".to_string(),
            message: if payment_result.success {
                "Your order has been confirmed!"
            } else {
                "Payment failed. Please try again."
            }.to_string(),
            data: Some(serde_json::json!({
                "orderId": event.order_id,
                "amount": event.total_amount
            })),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(24)),
        };

        self.send_user_notification(notification).await?;

        Ok(())
    }
}
```

### WebSocket Real-time Communication
```rust
async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(handlers): State<Arc<RwLock<HandlerRegistry>>>,
) -> Response {
    ws.on_upgrade(|socket| handle_websocket(socket, handlers))
}

async fn handle_websocket(
    socket: WebSocket,
    handlers: Arc<RwLock<HandlerRegistry>>,
) {
    let (mut sender, mut receiver) = socket.split();

    // Handle incoming WebSocket messages
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                // Parse and route WebSocket messages
                if let Ok(request) = serde_json::from_str::<WebSocketRequest>(&text) {
                    match request.type_field.as_str() {
                        "subscribe_notifications" => {
                            // Subscribe user to notifications
                        }
                        "subscribe_metrics" => {
                            // Subscribe to dashboard metrics
                        }
                        _ => {
                            warn!("Unknown WebSocket message type: {}", request.type_field);
                        }
                    }
                }
            }
            Ok(Message::Close(_)) => break,
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }
}
```

## Usage

### 1. Generate the Multi-Protocol Server

```bash
# From the root of the rust-template repository
asyncapi generate fromTemplate examples/multi-protocol/asyncapi.yaml . --output examples/multi-protocol/generated --force-write
```

### 2. Set Up Infrastructure

#### MQTT Broker
```bash
docker run -it -p 1883:1883 eclipse-mosquitto
```

#### Kafka Cluster
```bash
# Using Docker Compose
cat > docker-compose.yml << EOF
version: '3.8'
services:
  zookeeper:
    image: confluentinc/cp-zookeeper:latest
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000

  kafka:
    image: confluentinc/cp-kafka:latest
    depends_on:
      - zookeeper
    ports:
      - "9092:9092"
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
EOF

docker-compose up -d
```

### 3. Configure Environment

Create `.env` file:
```bash
# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
LOG_LEVEL=info

# MQTT Configuration
MQTT_HOST=localhost
MQTT_PORT=1883
MQTT_CLIENT_ID=event-processor

# Kafka Configuration
KAFKA_BROKERS=localhost:9092
KAFKA_GROUP_ID=event-processor
KAFKA_AUTO_OFFSET_RESET=earliest

# WebSocket Configuration
WEBSOCKET_PORT=8080

# HTTP API Configuration
HTTP_API_PORT=8081

# Database Configuration
DATABASE_URL=postgresql://user:password@localhost/events_db
```

### 4. Run the Generated Server

```bash
cd examples/multi-protocol/generated
cargo run
```

### 5. Test the Multi-Protocol System

#### Send IoT Sensor Data (MQTT)
```bash
mosquitto_pub -h localhost -t "iot/sensors/temp001/data" -m '{
  "sensorId": "temp001",
  "timestamp": "2024-01-15T10:30:00Z",
  "type": "temperature",
  "value": 85.5,
  "unit": "celsius",
  "location": {
    "latitude": 37.7749,
    "longitude": -122.4194,
    "address": "San Francisco, CA"
  }
}'
```

#### Publish User Event (Kafka)
```bash
# Create Kafka topic
kafka-topics --create --topic events.user.created --bootstrap-server localhost:9092

# Publish user created event
kafka-console-producer --topic events.user.created --bootstrap-server localhost:9092
{"userId":"123e4567-e89b-12d3-a456-426614174000","email":"user@example.com","username":"newuser","createdAt":"2024-01-15T10:30:00Z","source":"web"}
```

#### Connect via WebSocket
```javascript
// JavaScript client example
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onopen = function() {
    // Subscribe to notifications
    ws.send(JSON.stringify({
        type: 'subscribe_notifications',
        userId: '123e4567-e89b-12d3-a456-426614174000'
    }));

    // Subscribe to dashboard metrics
    ws.send(JSON.stringify({
        type: 'subscribe_metrics'
    }));
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    console.log('Received:', data);
};
```

#### Send HTTP Webhook
```bash
curl -X POST http://localhost:8081/api/webhooks/external \
  -H "Content-Type: application/json" \
  -d '{
    "webhookId": "webhook_123",
    "source": "payment_service",
    "event": "payment_completed",
    "data": {
      "paymentId": "pay_456",
      "amount": 99.99,
      "currency": "USD"
    },
    "timestamp": "2024-01-15T10:30:00Z",
    "signature": "sha256=abc123..."
  }'
```

## Advanced Features

### 1. **Event Correlation**
```rust
impl EventProcessor {
    async fn correlate_events(&self, event: &dyn Event) -> Result<Vec<CorrelatedEvent>> {
        // Find related events across protocols
        let related_events = self.event_store
            .find_related_events(event.correlation_id())
            .await?;

        // Apply correlation rules
        self.apply_correlation_rules(event, related_events).await
    }
}
```

### 2. **Protocol Translation**
```rust
impl ProtocolTranslator {
    async fn translate_mqtt_to_kafka(&self, mqtt_msg: MqttMessage) -> Result<KafkaMessage> {
        // Convert MQTT message to Kafka event
        let kafka_event = KafkaMessage {
            topic: format!("mqtt.{}", mqtt_msg.topic.replace('/', '.')),
            key: mqtt_msg.client_id,
            value: mqtt_msg.payload,
            headers: self.create_headers(&mqtt_msg),
        };

        Ok(kafka_event)
    }
}
```

### 3. **Real-time Metrics**
```rust
impl MetricsCollector {
    async fn collect_protocol_metrics(&self) -> DashboardMetricsPayload {
        DashboardMetricsPayload {
            timestamp: Utc::now(),
            metrics: Metrics {
                active_users: self.websocket_connections.len() as i32,
                total_orders: self.order_counter.load(Ordering::Relaxed),
                revenue: self.revenue_counter.load(Ordering::Relaxed) as f64 / 100.0,
                error_rate: self.calculate_error_rate(),
                response_time: self.average_response_time(),
            },
            alerts: self.get_active_alerts(),
        }
    }
}
```

### 4. **Circuit Breaker Pattern**
```rust
impl ProtocolHandler {
    async fn handle_with_circuit_breaker<T, F>(&self, operation: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        match self.circuit_breaker.state() {
            CircuitBreakerState::Closed => {
                match operation.await {
                    Ok(result) => {
                        self.circuit_breaker.record_success();
                        Ok(result)
                    }
                    Err(e) => {
                        self.circuit_breaker.record_failure();
                        Err(e)
                    }
                }
            }
            CircuitBreakerState::Open => {
                Err(anyhow::anyhow!("Circuit breaker is open"))
            }
            CircuitBreakerState::HalfOpen => {
                // Try operation and update circuit breaker state
                operation.await
            }
        }
    }
}
```

## Production Considerations

### 1. **Scalability**
- Use connection pooling for all protocols
- Implement horizontal scaling with load balancers
- Use Kafka partitioning for parallel processing
- Implement WebSocket connection management

### 2. **Reliability**
- Add retry mechanisms with exponential backoff
- Implement dead letter queues for failed messages
- Use persistent connections with reconnection logic
- Add health checks for all protocol handlers

### 3. **Security**
- Implement authentication for all protocols
- Use TLS/SSL for all connections
- Add rate limiting and DDoS protection
- Validate and sanitize all incoming messages

### 4. **Monitoring**
- Add comprehensive metrics collection
- Implement distributed tracing
- Set up alerting for critical issues
- Use structured logging across all protocols

## Related Examples

- [Simple Example](../simple/README.md) - Basic message handling patterns
- [MQTT Example](../mqtt/README.md) - Deep dive into MQTT integration
