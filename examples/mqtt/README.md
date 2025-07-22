# IoT Device Management Service - MQTT Example

This example demonstrates a comprehensive MQTT-based IoT device management system using the AsyncAPI Rust template. It showcases real-world MQTT patterns and complex message handling scenarios.

## Overview

This example demonstrates:
- **MQTT Protocol Integration**: Complete MQTT broker connectivity with rumqttc
- **Topic Patterns**: Dynamic topic routing with parameters (`devices/{deviceId}/telemetry`)
- **Bidirectional Communication**: Both subscribe and publish operations
- **Complex Data Models**: Nested schemas with validation and enums
- **Real-world IoT Patterns**: Telemetry, commands, status updates, and alerts

## Architecture

```
┌─────────────────┐    MQTT     ┌─────────────────┐    Commands    ┌─────────────────┐
│   IoT Devices   │◄──────────►│  Rust Server    │◄─────────────►│  Control Panel  │
│                 │             │                 │                │                 │
│ • Sensors       │             │ • Telemetry     │                │ • Device Mgmt   │
│ • Actuators     │             │ • Commands      │                │ • Monitoring    │
│ • Status        │             │ • Alerts        │                │ • Alerts        │
└─────────────────┘             └─────────────────┘                └─────────────────┘
```

## AsyncAPI Specification Features

### Channels
- `devices/{deviceId}/telemetry` - Receive sensor data from devices
- `devices/{deviceId}/commands` - Send commands to specific devices
- `devices/{deviceId}/status` - Monitor device health and status
- `alerts/critical` - Publish critical system alerts
- `system/heartbeat` - Service health monitoring

### Message Types
- **TelemetryData**: Sensor readings, location, and metadata
- **DeviceCommand**: Control commands with priority and expiration
- **DeviceStatus**: Health metrics and error reporting
- **CriticalAlert**: High-priority system alerts
- **SystemHeartbeat**: Service health signals

## Generated Code Structure

### Message Models (`src/models.rs`)
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryPayload {
    pub device_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub sensors: SensorReadings,
    pub location: Option<Location>,
    pub metadata: Option<DeviceMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorReadings {
    pub temperature: Option<f64>,
    pub humidity: Option<f64>,
    pub pressure: Option<f64>,
    pub battery: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandPayload {
    pub command_id: uuid::Uuid,
    pub device_id: String,
    pub command: CommandType,
    pub parameters: Option<serde_json::Value>,
    pub priority: Option<Priority>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommandType {
    Reboot,
    UpdateFirmware,
    ChangeInterval,
    Calibrate,
    Shutdown,
}
```

### MQTT Handler Implementation (`src/handlers.rs`)
```rust
impl DevicesTelemetryHandler {
    pub async fn handle_device_telemetry(&self, payload: &[u8]) -> Result<()> {
        let telemetry: TelemetryPayload = serde_json::from_slice(payload)?;

        info!("Received telemetry from device: {}", telemetry.device_id);

        // Process sensor data
        if let Some(temp) = telemetry.sensors.temperature {
            if temp > 80.0 {
                warn!("High temperature alert: {}°C on device {}", temp, telemetry.device_id);
                // Trigger alert
                self.send_critical_alert(&telemetry.device_id, "High temperature").await?;
            }
        }

        // Store telemetry data
        // self.database.store_telemetry(telemetry).await?;

        Ok(())
    }
}

impl DevicesCommandsHandler {
    pub async fn send_device_command(&self, device_id: &str, command: CommandPayload) -> Result<()> {
        let topic = format!("devices/{}/commands", device_id);
        let payload = serde_json::to_vec(&command)?;

        info!("Sending command {} to device {}", command.command_id, device_id);

        // Publish command via MQTT
        // self.mqtt_client.publish(&topic, payload).await?;

        Ok(())
    }
}
```

### MQTT Server Integration (`src/server.rs`)
```rust
impl Server {
    pub async fn start_mqtt_handler(&self) -> Result<()> {
        info!("Starting MQTT handler");

        let mut mqttoptions = rumqttc::MqttOptions::new(
            "iot-device-manager",
            &self.config.mqtt_config.host,
            self.config.mqtt_config.port
        );

        mqttoptions.set_keep_alive(Duration::from_secs(30));
        mqttoptions.set_clean_session(true);

        let (client, mut eventloop) = rumqttc::AsyncClient::new(mqttoptions, 10);

        // Subscribe to device topics
        client.subscribe("devices/+/telemetry", rumqttc::QoS::AtLeastOnce).await?;
        client.subscribe("devices/+/status", rumqttc::QoS::AtLeastOnce).await?;

        let handlers = self.handlers.clone();
        tokio::spawn(async move {
            loop {
                match eventloop.poll().await {
                    Ok(rumqttc::Event::Incoming(rumqttc::Packet::Publish(publish))) => {
                        let topic = &publish.topic;
                        let payload = &publish.payload;

                        // Route messages based on topic pattern
                        if topic.contains("/telemetry") {
                            if let Err(e) = handlers.read().await
                                .devices_telemetry_handler
                                .handle_device_telemetry(payload).await
                            {
                                error!("Failed to handle telemetry: {}", e);
                            }
                        } else if topic.contains("/status") {
                            if let Err(e) = handlers.read().await
                                .devices_status_handler
                                .handle_device_status(payload).await
                            {
                                error!("Failed to handle status: {}", e);
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        error!("MQTT connection error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }
}
```

## Usage

### 1. Generate the Rust Server

```bash
# From the root of the rust-template repository
asyncapi generate fromTemplate examples/mqtt/asyncapi.yaml . --output examples/mqtt/generated --force-write
```

### 2. Set Up MQTT Broker

Using Docker:
```bash
docker run -it -p 1883:1883 -p 9001:9001 eclipse-mosquitto
```

Or install locally:
```bash
# Ubuntu/Debian
sudo apt-get install mosquitto mosquitto-clients

# macOS
brew install mosquitto
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
MQTT_CLIENT_ID=iot-device-manager
MQTT_KEEP_ALIVE=30
MQTT_CLEAN_SESSION=true

# Optional: MQTT Authentication
MQTT_USERNAME=
MQTT_PASSWORD=

# Database Configuration (for storing telemetry)
DATABASE_URL=postgresql://user:password@localhost/iot_db
```

### 4. Run the Generated Server

```bash
cd examples/mqtt/generated
cargo run
```

### 5. Test with MQTT Clients

#### Send Telemetry Data
```bash
mosquitto_pub -h localhost -t "devices/sensor001/telemetry" -m '{
  "deviceId": "sensor001",
  "timestamp": "2024-01-15T10:30:00Z",
  "sensors": {
    "temperature": 23.5,
    "humidity": 65.2,
    "pressure": 1013.25,
    "battery": 87.3
  },
  "location": {
    "latitude": 37.7749,
    "longitude": -122.4194
  }
}'
```

#### Send Device Status
```bash
mosquitto_pub -h localhost -t "devices/sensor001/status" -m '{
  "deviceId": "sensor001",
  "status": "online",
  "health": {
    "cpu": 45.2,
    "memory": 67.8,
    "disk": 23.1,
    "uptime": 86400
  },
  "lastSeen": "2024-01-15T10:30:00Z"
}'
```

#### Listen for Commands
```bash
mosquitto_sub -h localhost -t "devices/+/commands"
```

## Advanced Features

### 1. **Topic Pattern Matching**
The server automatically extracts device IDs from topic patterns:
```rust
// Topic: devices/sensor001/telemetry
// Extracted deviceId: "sensor001"
```

### 2. **Message Validation**
All incoming messages are validated against the AsyncAPI schema:
```rust
// Automatic validation of required fields, data types, and constraints
if telemetry.sensors.temperature.unwrap_or(0.0) > 100.0 {
    return Err(anyhow::anyhow!("Temperature out of range"));
}
```

### 3. **Error Handling and Resilience**
```rust
impl DevicesTelemetryHandler {
    pub async fn handle_device_telemetry(&self, payload: &[u8]) -> Result<()> {
        let telemetry = match serde_json::from_slice::<TelemetryPayload>(payload) {
            Ok(data) => data,
            Err(e) => {
                warn!("Invalid telemetry data: {}", e);
                // Log invalid message for debugging
                return Ok(()); // Don't crash on invalid data
            }
        };

        // Process valid telemetry...
        Ok(())
    }
}
```

### 4. **Custom Business Logic Examples**

#### Temperature Monitoring
```rust
async fn monitor_temperature(&self, telemetry: &TelemetryPayload) -> Result<()> {
    if let Some(temp) = telemetry.sensors.temperature {
        match temp {
            t if t > 80.0 => {
                self.send_critical_alert(&telemetry.device_id, "Critical temperature").await?;
            }
            t if t > 60.0 => {
                self.send_warning(&telemetry.device_id, "High temperature").await?;
            }
            _ => {}
        }
    }
    Ok(())
}
```

#### Device Command Scheduling
```rust
async fn schedule_maintenance(&self, device_id: &str) -> Result<()> {
    let command = CommandPayload {
        command_id: Uuid::new_v4(),
        device_id: device_id.to_string(),
        command: CommandType::Calibrate,
        parameters: None,
        priority: Some(Priority::Normal),
        expires_at: Some(Utc::now() + Duration::hours(24)),
        created_at: Utc::now(),
    };

    self.send_device_command(device_id, command).await
}
```

## Production Considerations

### 1. **Security**
- Enable TLS/SSL for MQTT connections
- Implement device authentication
- Use access control lists (ACLs)

### 2. **Scalability**
- Implement connection pooling
- Use MQTT broker clustering
- Add message queuing for high throughput

### 3. **Monitoring**
- Implement health checks
- Add metrics collection
- Set up alerting for critical issues

### 4. **Data Persistence**
- Store telemetry data in time-series database
- Implement data retention policies
- Add backup and recovery procedures

## Related Examples

- [Simple Example](../simple/README.md) - Basic message handling patterns
- [Multi-Protocol Example](../multi-protocol/README.md) - Combining MQTT with other protocols
