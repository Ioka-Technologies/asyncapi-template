/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default ({ asyncapi, params }) => {
  // Check if auth feature is enabled
  const enableAuth = params.enableAuth === 'true' || params.enableAuth === true;
  // Simple case conversion functions
  const pascalCase = (str) => {
    return str.replace(/(?:^|[-_])(\w)/g, (_, c) => c.toUpperCase());
  };

  const camelCase = (str) => {
    const pascal = pascalCase(str);
    return pascal.charAt(0).toLowerCase() + pascal.slice(1);
  };

  function toRustFieldName(str) {
    if (!str) return 'unknown';
    return str
      .replace(/[^a-zA-Z0-9_]/g, '_')
      .replace(/^[0-9]/, '_$&')
      .replace(/_+/g, '_')
      .replace(/^_+|_+$/g, '')
      .replace(/([A-Z])/g, '_$1')
      .toLowerCase()
      .replace(/^_/, '');
  }

  // Get the first few channels for the example
  const channels = asyncapi.channels();
  const channelArray = Array.from(channels.values()).slice(0, 2); // Take first 2 channels for simplicity

  // Get operations for examples
  const operations = asyncapi.operations();
  const operationArray = Array.from(operations.values()).slice(0, 3); // Take first 3 operations

  // Get message schemas for examples
  const messages = asyncapi.allMessages();
  const messageArray = Array.from(messages.values()).slice(0, 3); // Take first 3 messages

  // Process channel data for AutoServerBuilder examples
  const channelData = [];
  if (channels) {
    for (const channel of channels) {
      const channelName = channel.id();
      const channelOps = [];

      // Find operations that reference this channel
      if (operations) {
        for (const operation of operations) {
          try {
            const embeddedChannel = operation._json && operation._json.channel;
            if (embeddedChannel) {
              const embeddedChannelId = embeddedChannel['x-parser-unique-object-id'];
              if (embeddedChannelId === channelName) {
                const action = operation.action && operation.action();
                const messages = operation.messages && operation.messages();
                const reply = operation.reply && operation.reply();

                channelOps.push({
                  name: operation.id(),
                  action,
                  messages: messages || [],
                  reply: reply,
                });
              }
            }
          } catch (e) {
            // Skip operations that cause errors
          }
        }
      }

      // Analyze operation patterns
      const patterns = [];
      for (const op of channelOps) {
        if (op.reply) {
          patterns.push({ type: 'request_response', operation: op });
        } else if (op.action === 'send') {
          patterns.push({ type: 'request_only', operation: op });
        }
      }

      channelData.push({
        name: channelName,
        fieldName: toRustFieldName(channelName + '_handler'),
        patterns: patterns
      });
    }
  }

  return (
    <File name="USAGE.md">
      {`# Usage Guide: From AsyncAPI Spec to Production Service

**The Strategic Approach**: This guide demonstrates how to transform your AsyncAPI specification into a production-ready service that scales with your business needs while maintaining clean separation between infrastructure and domain logic.

## The Development Philosophy

**Traditional Problem**: Most async messaging tutorials focus on "how to send a message" rather than "how to build sustainable business systems."

**Our Approach**: We focus on **architectural patterns** that solve real business problems:
- 🎯 **Domain-Driven Design**: Your business logic drives the architecture, not the transport protocol
- 🔄 **Evolutionary Architecture**: Services that adapt to changing requirements without rewrites
- 🛡️ **Failure Resilience**: Built-in patterns for handling the chaos of distributed systems
- 📈 **Production Readiness**: From day one, your service can handle real-world load and complexity

## The 5-Minute Production Service

**Business Scenario**: You're building a user onboarding service that needs to handle real-time signups, send welcome emails, and track analytics - all while maintaining sub-second response times.

### Step 1: Implement Your Business Logic (2 minutes)

\`\`\`rust
use std::sync::Arc;
use ${camelCase(asyncapi.info().title().replace(/[^a-zA-Z0-9]/g, '_'))}_service::*;
use async_trait::async_trait;

// This is YOUR domain logic - never touched by regeneration
pub struct UserOnboardingService {
    database: Arc<Database>,
    email_service: Arc<EmailService>,
    analytics: Arc<Analytics>,
    notification_service: Arc<NotificationService>,
}

#[async_trait]
impl UserSignupService for UserOnboardingService {
    async fn handle_user_signup(&self, request: UserSignup, ctx: &MessageContext) -> AsyncApiResult<UserWelcome> {
        // Pure business logic - no infrastructure concerns

        // 1. Business validation (your domain rules)
        if !self.is_valid_business_email(&request.email) {
            return Err(AsyncApiError::business_rule("Corporate email required"));
        }

        // 2. Execute business workflow
        let user = self.database.create_user_with_profile(&request).await?;

        // 3. Trigger business processes (async, non-blocking)
        tokio::spawn({
            let email_service = self.email_service.clone();
            let analytics = self.analytics.clone();
            let user_id = user.id.clone();
            let email = request.email.clone();

            async move {
                // Welcome email with onboarding sequence
                let _ = email_service.send_welcome_sequence(&email, &user_id).await;

                // Business analytics (user acquisition funnel)
                let _ = analytics.track_user_acquisition(&user_id, "signup_completed").await;
            }
        });

        // 4. Return immediate response (infrastructure handles routing)
        Ok(UserWelcome {
            user_id: user.id,
            message: format!("Welcome to the platform, {}!", user.display_name),
            onboarding_url: self.generate_personalized_onboarding(&user).await?,
            next_steps: self.get_onboarding_checklist(&user).await?,
        })
    }
}

impl UserOnboardingService {
    // Your domain methods - this is where business value lives
    async fn is_valid_business_email(&self, email: &str) -> bool {
        // Business rule: only allow corporate domains
        !email.ends_with("@gmail.com") && !email.ends_with("@yahoo.com")
    }

    async fn generate_personalized_onboarding(&self, user: &User) -> AsyncApiResult<String> {
        // Business logic: personalize onboarding based on user profile
        let role = self.detect_user_role(&user).await?;
        Ok(format!("https://app.company.com/onboarding/{}", role))
    }
}
\`\`\`

### Step 2: Start Your Service (1 minute)

\`\`\`rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize observability
    tracing_subscriber::fmt()
        .with_env_filter("info,user_onboarding=debug")
        .init();

    // Create your business service with dependencies
    let service = Arc::new(UserOnboardingService::new(
        database_pool,
        email_service,
        analytics_client,
        notification_service,
    ));

    // AutoServerBuilder: Zero-config production deployment
    AutoServerBuilder::new()${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).slice(0, 2).map(channel => `
        .with_${channel.fieldName}_service(service.clone())`).join('')}
        .with_health_checks(true)           // Kubernetes readiness/liveness
        .with_metrics_endpoint("/metrics")  // Prometheus monitoring
        .with_graceful_shutdown(30)         // Zero-downtime deployments
        .build_and_start()
        .await?;

    Ok(())
}
\`\`\`

### Step 3: Deploy and Scale (2 minutes)

\`\`\`bash
# Build optimized production binary
cargo build --release

# Docker deployment
docker build -t user-onboarding-service .
docker run -p 8080:8080 user-onboarding-service

# Kubernetes deployment (auto-scaling enabled)
kubectl apply -f k8s/deployment.yaml

# The service automatically:
# ✅ Handles 1000+ concurrent WebSocket connections
# ✅ Processes signup requests in <100ms
# ✅ Recovers from database failures with retries
# ✅ Scales horizontally based on load
# ✅ Provides health checks for orchestration
# ✅ Exports metrics for monitoring
\`\`\`

**Result**: You now have a production-ready user onboarding service that can handle real business load while maintaining clean, testable business logic.

${enableAuth ? `## Authentication Support

When your AsyncAPI specification includes authentication requirements, the generated server automatically handles authentication and authorization:

\`\`\`rust
use std::sync::Arc;
use ${camelCase(asyncapi.info().title().replace(/[^a-zA-Z0-9]/g, '_'))}_service::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::init();

    // Create your service implementation
    let my_service = Arc::new(MyService::new());

    // Authentication is automatically configured based on your AsyncAPI spec
    // Just provide the necessary secrets/configuration
    AutoServerBuilder::new()${channelData.filter(channel => channel.patterns.some(p => p.type === 'request_response' || p.type === 'request_only')).slice(0, 2).map(channel => `
        .with_${channel.fieldName}_service(my_service.clone())`).join('')}
        .with_jwt_secret("your-secret-key") // For JWT authentication
        .with_basic_auth_users(users_db)    // For Basic authentication
        .with_api_keys(api_keys_db)         // For API Key authentication
        .build_and_start()
        .await?;

    Ok(())
}
\`\`\`

### Automatic Authentication Handling

The generated server automatically:

- **Validates Authentication**: Checks JWT tokens, Basic Auth credentials, or API keys based on your AsyncAPI security schemes
- **Enforces Authorization**: Applies operation-level security requirements automatically
- **Provides User Context**: Makes authenticated user information available in your handlers
- **Handles Auth Errors**: Returns appropriate error responses for authentication failures

### Accessing User Information

In your service implementations, authenticated user information is automatically available:

\`\`\`rust
#[async_trait]
impl UserSignupService for MyUserService {
    async fn handle_signup(&self, request: SignupRequest, context: &MessageContext) -> AsyncApiResult<SignupResponse> {
        // User information is automatically available when authentication is required
        if let Some(claims) = context.claims() {
            println!("Authenticated user: {}", claims.sub);
            println!("User roles: {:?}", claims.roles);
            println!("User permissions: {:?}", claims.permissions);

            // Use authentication context for business logic
            let user_id = &claims.sub;
            // Your business logic here...
        }

        // For public operations, claims() returns None
        let response = SignupResponse {
            user_id: request.id,
            status: "success".to_string(),
        };
        Ok(response)
    }
}
\`\`\`

### AsyncAPI Security Configuration

Authentication is configured in your AsyncAPI specification:

\`\`\`yaml
# Security schemes define available authentication methods
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
    basicAuth:
      type: http
      scheme: basic
    apiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key

# Server-level security applies to all operations
servers:
  production:
    host: api.example.com
    protocol: wss
    security:
      - bearerAuth: []

# Operation-level security overrides server security
operations:
  handleUserSignup:
    action: send
    security:
      - bearerAuth: []
      - apiKeyAuth: []  # Alternative auth methods
    # ... rest of operation definition
\`\`\`

The generated server automatically enforces these security requirements without any additional code needed in your service implementations.

` : ''}

## Why This Architecture Wins in Production

**The Strategic Advantage**: AutoServerBuilder eliminates the gap between "demo code" and "production systems."

### Traditional AsyncAPI Development Problems

**❌ Infrastructure Complexity**:
- Manual transport configuration for each protocol
- Custom routing logic that breaks with spec changes
- Error handling that's an afterthought
- Monitoring and observability bolted on later

**❌ Business Logic Pollution**:
- Domain logic mixed with protocol concerns
- Tight coupling between message formats and business rules
- Testing requires mocking complex infrastructure
- Changes to transport break business logic

**❌ Production Readiness Gap**:
- Demo code that doesn't handle real-world failures
- No built-in monitoring or health checks
- Manual scaling and deployment configuration
- Security and authentication as separate concerns

### Our Solution: Production-First Architecture

**✅ Infrastructure Automation**:
| Traditional Approach | AutoServerBuilder |
|---------------------|-------------------|
| 50+ lines of transport setup | 🎯 **Zero-config from AsyncAPI spec** |
| Manual routing configuration | 🔄 **Automatic operation routing** |
| Custom error handling | 🛡️ **Built-in recovery patterns** |
| Protocol-specific business code | 🌐 **Protocol-agnostic service logic** |
| Separate monitoring setup | 📊 **Integrated observability** |

**✅ Business Logic Protection**:
- **Domain Purity**: Business logic has zero infrastructure dependencies
- **Test Simplicity**: Mock the trait interface, test business rules in isolation
- **Change Resilience**: Protocol evolution never touches domain code
- **Specification Driven**: AsyncAPI spec changes automatically update infrastructure

**✅ Production Readiness**:
- **Day-One Monitoring**: Prometheus metrics, structured logging, health checks
- **Failure Resilience**: Circuit breakers, retries, graceful degradation
- **Zero-Downtime Deployment**: Graceful shutdown, connection draining
- **Horizontal Scaling**: Stateless design enables automatic scaling

## Real-World Architecture Patterns

**The Business Context**: Your AsyncAPI specification isn't just a message format - it's your **service contract** that defines how your business capabilities are exposed to the world.

### Pattern 1: Request/Response Services (Synchronous Business Logic)

**Use Case**: User authentication, data validation, immediate business decisions

**AsyncAPI Pattern**:
\`\`\`yaml
operations:
  authenticateUser:
    action: send
    channel: { $ref: '#/channels/auth' }
    reply:
      channel: { $ref: '#/channels/auth' }
      messages: [{ $ref: '#/components/messages/AuthResponse' }]
\`\`\`

**Business Implementation**:
\`\`\`rust
#[async_trait]
impl AuthService for BusinessAuthService {
    async fn handle_authenticate_user(&self, request: AuthRequest, ctx: &MessageContext) -> AsyncApiResult<AuthResponse> {
        // Immediate business decision - user can/cannot access system
        let user = self.validate_credentials(&request.email, &request.password).await?;
        let session = self.create_secure_session(&user).await?;

        Ok(AuthResponse {
            success: true,
            session_token: session.token,
            expires_at: session.expires_at,
            user_profile: user.to_public_profile(),
        })
    }
}
\`\`\`

### Pattern 2: Event-Driven Services (Asynchronous Business Processes)

**Use Case**: Order processing, notification delivery, analytics tracking

**AsyncAPI Pattern**:
\`\`\`yaml
operations:
  processOrder:
    action: send
    channel: { $ref: '#/channels/orders' }
    # No reply - fire-and-forget for async processing
\`\`\`

**Business Implementation**:
\`\`\`rust
#[async_trait]
impl OrderService for BusinessOrderService {
    async fn handle_process_order(&self, order: OrderRequest, ctx: &MessageContext) -> AsyncApiResult<()> {
        // Trigger business workflow - don't wait for completion
        let order_id = self.create_order_record(&order).await?;

        // Async business processes (non-blocking)
        self.trigger_payment_processing(order_id).await?;
        self.trigger_inventory_reservation(order_id).await?;
        self.trigger_shipping_calculation(order_id).await?;

        // Return immediately - business processes continue in background
        Ok(())
    }
}
\`\`\`

### Pattern 3: Streaming Services (Real-Time Business Intelligence)

**Use Case**: Live dashboards, real-time analytics, monitoring systems

**AsyncAPI Pattern**:
\`\`\`yaml
operations:
  streamMetrics:
    action: receive  # Server publishes to clients
    channel: { $ref: '#/channels/metrics' }
\`\`\`

**Business Implementation**:
\`\`\`rust
impl MetricsService {
    pub async fn start_business_metrics_stream(&self) -> AsyncApiResult<()> {
        let mut interval = tokio::time::interval(Duration::from_secs(5));

        loop {
            interval.tick().await;

            // Gather real-time business metrics
            let metrics = BusinessMetrics {
                active_users: self.get_active_user_count().await?,
                revenue_today: self.get_daily_revenue().await?,
                orders_per_minute: self.get_order_velocity().await?,
                system_health: self.get_system_health().await?,
            };

            // Broadcast to all connected dashboards
            self.broadcast_to_subscribers("metrics", &metrics).await?;
        }
    }
}
\`\`\`

## Complete AsyncAPI Specification Example

**Strategic Design**: This specification demonstrates how to design AsyncAPI for real business systems, not just technical demos.

\`\`\`yaml
asyncapi: 3.0.0
info:
  title: Real-time User Service
  version: 1.0.0
  description: |
    A WebSocket-based user service demonstrating real-time request/response patterns.
    This service provides instant feedback for user operations while maintaining
    connection state for optimal user experience.
  contact:
    name: AsyncAPI Community
    url: https://asyncapi.com
  license:
    name: Apache 2.0
    url: https://www.apache.org/licenses/LICENSE-2.0

servers:
  production:
    host: api.example.com
    protocol: wss
    description: Production WebSocket server with TLS
    security:
      - bearerAuth: []
  development:
    host: localhost:8080
    protocol: ws
    description: Local development WebSocket server
  staging:
    host: staging.example.com
    protocol: wss
    description: Staging environment with TLS

channels:
  userSignup:
    address: /ws/user/signup
    description: |
      Real-time user registration channel that provides immediate feedback.
      Clients connect to this channel to register new users and receive
      instant confirmation with onboarding resources.
    messages:
      userSignup:
        $ref: '#/components/messages/UserSignup'
      userWelcome:
        $ref: '#/components/messages/UserWelcome'

  userProfile:
    address: /ws/user/profile
    description: |
      User profile management channel for real-time profile updates.
      Supports both profile queries and updates with immediate validation feedback.
    messages:
      profileQuery:
        $ref: '#/components/messages/ProfileQuery'
      profileUpdate:
        $ref: '#/components/messages/ProfileUpdate'
      profileResponse:
        $ref: '#/components/messages/ProfileResponse'

operations:
  handleUserSignup:
    action: send
    channel:
      $ref: '#/channels/userSignup'
    summary: Process user registration with instant feedback
    description: |
      Handles new user registration requests and provides immediate feedback
      through the WebSocket connection. This enables real-time validation
      and instant onboarding experience without page refreshes.
    messages:
      - $ref: '#/channels/userSignup/messages/userSignup'
    reply:
      channel:
        $ref: '#/channels/userSignup'
      messages:
        - $ref: '#/channels/userSignup/messages/userWelcome'

  handleProfileQuery:
    action: send
    channel:
      $ref: '#/channels/userProfile'
    summary: Query user profile information
    description: |
      Retrieves user profile information in real-time. This operation
      demonstrates how to implement query patterns over WebSocket for
      instant data retrieval without HTTP overhead.
    messages:
      - $ref: '#/channels/userProfile/messages/profileQuery'
    reply:
      channel:
        $ref: '#/channels/userProfile'
      messages:
        - $ref: '#/channels/userProfile/messages/profileResponse'

  handleProfileUpdate:
    action: send
    channel:
      $ref: '#/channels/userProfile'
    summary: Update user profile with validation
    description: |
      Updates user profile information with real-time validation feedback.
      Provides instant confirmation of changes and validation errors
      without requiring form resubmission.
    messages:
      - $ref: '#/channels/userProfile/messages/profileUpdate'
    reply:
      channel:
        $ref: '#/channels/userProfile'
      messages:
        - $ref: '#/channels/userProfile/messages/profileResponse'

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
      description: JWT token for WebSocket authentication

  messages:
    UserSignup:
      name: UserSignup
      title: User Registration Request
      summary: Real-time user registration with validation
      contentType: application/json
      payload:
        $ref: '#/components/schemas/UserSignupPayload'

    UserWelcome:
      name: UserWelcome
      title: User Welcome Response
      summary: Instant welcome message with onboarding resources
      contentType: application/json
      payload:
        $ref: '#/components/schemas/UserWelcomePayload'

    ProfileQuery:
      name: ProfileQuery
      title: Profile Information Query
      summary: Request for user profile data
      contentType: application/json
      payload:
        $ref: '#/components/schemas/ProfileQueryPayload'

    ProfileUpdate:
      name: ProfileUpdate
      title: Profile Update Request
      summary: Real-time profile modification request
      contentType: application/json
      payload:
        $ref: '#/components/schemas/ProfileUpdatePayload'

    ProfileResponse:
      name: ProfileResponse
      title: Profile Operation Response
      summary: Response for profile queries and updates
      contentType: application/json
      payload:
        $ref: '#/components/schemas/ProfileResponsePayload'

  schemas:
    UserSignupPayload:
      type: object
      description: User registration request with validation requirements
      properties:
        id:
          type: string
          format: uuid
          description: Client-generated unique identifier for request tracking
        username:
          type: string
          minLength: 3
          maxLength: 50
          pattern: '^[a-zA-Z0-9_]+$'
          description: Unique username for the account (alphanumeric and underscore only)
        email:
          type: string
          format: email
          description: Valid email address for account verification
        fullName:
          type: string
          maxLength: 100
          description: User's full display name
        password:
          type: string
          minLength: 8
          description: Secure password (will be hashed server-side)
        preferences:
          $ref: '#/components/schemas/UserPreferences'
        agreedToTerms:
          type: boolean
          description: Confirmation that user has agreed to terms of service
        createdAt:
          type: string
          format: date-time
          description: Client timestamp of registration attempt
      required:
        - id
        - username
        - email
        - password
        - agreedToTerms
        - createdAt

    UserWelcomePayload:
      type: object
      description: Welcome response with onboarding information
      properties:
        userId:
          type: string
          format: uuid
          description: Server-assigned unique user identifier
        username:
          type: string
          description: Confirmed username for the new account
        message:
          type: string
          description: Personalized welcome message
        onboardingSteps:
          type: array
          items:
            type: object
            properties:
              step:
                type: string
                description: Step identifier
              title:
                type: string
                description: Human-readable step title
              url:
                type: string
                format: uri
                description: Link to complete this step
          description: Guided onboarding process for new users
        resources:
          type: array
          items:
            type: string
            format: uri
          description: Helpful resources for getting started
        sessionToken:
          type: string
          description: JWT token for authenticated operations
      required:
        - userId
        - username
        - message
        - sessionToken

    ProfileQueryPayload:
      type: object
      description: Request for user profile information
      properties:
        userId:
          type: string
          format: uuid
          description: User identifier for profile lookup
        fields:
          type: array
          items:
            type: string
          description: Specific fields to retrieve (empty for all fields)
        includePreferences:
          type: boolean
          default: false
          description: Whether to include user preferences in response
      required:
        - userId

    ProfileUpdatePayload:
      type: object
      description: Profile modification request with change tracking
      properties:
        userId:
          type: string
          format: uuid
          description: User identifier for profile update
        changes:
          type: object
          description: Fields to update with new values
          properties:
            fullName:
              type: string
              maxLength: 100
            email:
              type: string
              format: email
            preferences:
              $ref: '#/components/schemas/UserPreferences'
        reason:
          type: string
          description: Optional reason for the profile update
        updatedAt:
          type: string
          format: date-time
          description: Client timestamp of update request
      required:
        - userId
        - changes
        - updatedAt

    ProfileResponsePayload:
      type: object
      description: Response for profile operations with status information
      properties:
        userId:
          type: string
          format: uuid
          description: User identifier
        success:
          type: boolean
          description: Whether the operation was successful
        profile:
          type: object
          description: Current profile information (for queries and successful updates)
          properties:
            username:
              type: string
            email:
              type: string
            fullName:
              type: string
            preferences:
              $ref: '#/components/schemas/UserPreferences'
            lastUpdated:
              type: string
              format: date-time
        errors:
          type: array
          items:
            type: object
            properties:
              field:
                type: string
                description: Field that caused the error
              message:
                type: string
                description: Human-readable error message
              code:
                type: string
                description: Machine-readable error code
          description: Validation or processing errors (if any)
        message:
          type: string
          description: Human-readable status message
      required:
        - userId
        - success
        - message

    UserPreferences:
      type: object
      description: User customization preferences
      properties:
        newsletter:
          type: boolean
          default: true
          description: Email newsletter subscription preference
        notifications:
          type: object
          properties:
            email:
              type: boolean
              default: true
            push:
              type: boolean
              default: false
            sms:
              type: boolean
              default: false
          description: Notification delivery preferences
        theme:
          type: string
          enum: [light, dark, auto]
          default: auto
          description: UI theme preference
        language:
          type: string
          default: en
          pattern: '^[a-z]{2}$'
          description: Preferred language code (ISO 639-1)
        timezone:
          type: string
          default: UTC
          description: User's timezone for date/time display
\`\`\`

**Key Architecture Points:**

🔄 **Request/Response Patterns:**
- \`handleUserSignup\` and \`handleProfileQuery\` operations have \`reply\` fields, enabling real-time request/response flows
- Responses are automatically sent back through the same WebSocket connection
- Correlation IDs track requests through the entire processing pipeline

🌐 **WebSocket Benefits:**
- **Real-time Feedback**: Instant validation and confirmation without page refreshes
- **Persistent Connection**: Maintains state for better user experience
- **Bidirectional Communication**: Server can push updates to clients
- **Lower Latency**: No HTTP overhead for each request

🔒 **Security Features:**
- JWT authentication for WebSocket connections
- TLS support (WSS) for production environments
- Request validation with detailed error responses

## Core Components

### TransportManager

The **TransportManager** is the heart of the messaging architecture, designed to provide:

**🔄 Protocol Abstraction**: Enables your business logic to work seamlessly across different transport protocols (WebSocket, HTTP, MQTT, Kafka) without code changes. This means you can switch from WebSocket to MQTT for IoT deployments or HTTP for simple REST APIs without rewriting your service logic.

**🎯 Intelligent Routing**: Routes incoming messages to the correct channel handlers based on message metadata. This eliminates the need for manual message dispatching and ensures messages reach their intended processors reliably.

**💪 Connection Resilience**: Monitors connection health and automatically handles reconnections, ensuring your service remains available even during network interruptions. This is especially important for WebSocket connections which can be dropped due to network issues.

**📊 Unified Interface**: Provides a consistent API for sending messages regardless of the underlying transport, simplifying your code and making it more maintainable.

### RecoveryManager

The **RecoveryManager** implements enterprise-grade reliability patterns to ensure your service can handle failures gracefully:

**🔄 Smart Retry Logic**: Uses exponential backoff to retry failed operations, preventing system overload while maximizing the chance of eventual success. This is crucial for handling temporary network issues or downstream service unavailability.

**⚡ Circuit Breaker Protection**: Automatically isolates failing services to prevent cascading failures that could bring down your entire system. When a service fails repeatedly, the circuit breaker opens to give it time to recover.

**📮 Dead Letter Queue**: Captures messages that cannot be processed after all retry attempts, ensuring no data is lost and allowing for manual investigation and reprocessing. This is essential for maintaining data integrity in production systems.

**📈 Comprehensive Monitoring**: Tracks error rates, retry attempts, and recovery patterns to help you identify and resolve systemic issues before they impact users.

## WebSocket Transport Configuration

### Why WebSocket for Real-time Services?

WebSocket provides several advantages for AsyncAPI services:

- **🚀 Low Latency**: No HTTP overhead for each request/response cycle
- **🔄 Bidirectional**: Server can push updates to clients instantly
- **💾 Stateful**: Maintains connection context for better user experience
- **⚡ Real-time**: Perfect for live validation, notifications, and collaborative features

### Server Configuration

\`\`\`rust
use crate::transport::{TransportManager, TransportConfig};
use crate::recovery::RecoveryManager;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize structured logging for better observability
    tracing_subscriber::fmt()
        .with_env_filter("info,your_service=debug")
        .init();

    // Configure WebSocket transport with production-ready settings
    let ws_config = TransportConfig {
        protocol: "wss".to_string(), // Use WSS for production (TLS encryption)
        host: "0.0.0.0".to_string(),
        port: 8080,
        tls: true, // Enable TLS for secure connections
        username: None, // WebSocket auth typically uses headers/tokens
        password: None,
        // Connection pool settings for handling multiple clients
        max_connections: Some(1000),
        connection_timeout: Some(std::time::Duration::from_secs(30)),
        // Keep-alive settings to detect dead connections
        keep_alive: Some(std::time::Duration::from_secs(60)),
        // Custom headers for authentication and CORS
        headers: {
            let mut headers = std::collections::HashMap::new();
            headers.insert("Access-Control-Allow-Origin".to_string(), "*".to_string());
            headers.insert("Access-Control-Allow-Headers".to_string(), "Authorization".to_string());
            headers
        },
    };

    // Create transport manager with WebSocket configuration
    let transport_manager = Arc::new(TransportManager::with_config(ws_config)?);

    // Configure recovery manager for production resilience
    let recovery_config = RecoveryConfig {
        max_retries: 3,
        initial_delay: std::time::Duration::from_millis(100),
        max_delay: std::time::Duration::from_secs(30),
        backoff_multiplier: 2.0,
        circuit_breaker_threshold: 5, // Open circuit after 5 consecutive failures
        circuit_breaker_timeout: std::time::Duration::from_secs(60),
    };
    let recovery_manager = Arc::new(RecoveryManager::with_config(recovery_config));

    // Your service setup continues here...
    Ok(())
}
\`\`\`

### Client Connection Examples

#### JavaScript/TypeScript Client

\`\`\`javascript
class AsyncAPIWebSocketClient {
    constructor(url, token) {
        this.url = url;
        this.token = token;
        this.ws = null;
        this.pendingRequests = new Map(); // Track request/response correlation
    }

    async connect() {
        return new Promise((resolve, reject) => {
            // Include JWT token in connection headers
            this.ws = new WebSocket(this.url, [], {
                headers: {
                    'Authorization': \`Bearer \${this.token}\`
                }
            });

            this.ws.onopen = () => {
                console.log('Connected to AsyncAPI WebSocket service');
                resolve();
            };

            this.ws.onmessage = (event) => {
                this.handleMessage(JSON.parse(event.data));
            };

            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                reject(error);
            };

            this.ws.onclose = (event) => {
                console.log('WebSocket connection closed:', event.code, event.reason);
                // Implement reconnection logic here
                this.reconnect();
            };
        });
    }

    // Send request and wait for response (request/response pattern)
    async sendRequest(channel, operation, payload) {
        const correlationId = this.generateCorrelationId();

        const message = {
            channel,
            operation,
            correlationId,
            timestamp: new Date().toISOString(),
            payload
        };

        return new Promise((resolve, reject) => {
            // Store the promise resolvers for when response arrives
            this.pendingRequests.set(correlationId, { resolve, reject });

            // Set timeout for request
            setTimeout(() => {
                if (this.pendingRequests.has(correlationId)) {
                    this.pendingRequests.delete(correlationId);
                    reject(new Error('Request timeout'));
                }
            }, 30000); // 30 second timeout

            this.ws.send(JSON.stringify(message));
        });
    }

    handleMessage(message) {
        const { correlationId, payload, error } = message;

        if (this.pendingRequests.has(correlationId)) {
            const { resolve, reject } = this.pendingRequests.get(correlationId);
            this.pendingRequests.delete(correlationId);

            if (error) {
                reject(new Error(error.message));
            } else {
                resolve(payload);
            }
        }
    }

    // Example: User signup with real-time response
    async signupUser(userData) {
        try {
            const response = await this.sendRequest(
                '/ws/user/signup',
                'handleUserSignup',
                {
                    id: this.generateUUID(),
                    username: userData.username,
                    email: userData.email,
                    fullName: userData.fullName,
                    password: userData.password,
                    agreedToTerms: true,
                    createdAt: new Date().toISOString()
                }
            );

            console.log('User registered successfully:', response);
            return response;
        } catch (error) {
            console.error('Registration failed:', error);
            throw error;
        }
    }

    generateCorrelationId() {
        return 'req_' + Math.random().toString(36).substr(2, 9);
    }

    generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
}

// Usage example
const client = new AsyncAPIWebSocketClient('wss://api.example.com/ws', 'your-jwt-token');
await client.connect();

// Real-time user registration
const welcomeResponse = await client.signupUser({
    username: 'johndoe',
    email: 'john@example.com',
    fullName: 'John Doe',
    password: 'securepassword123'
});
\`\`\`

#### Rust Client Example

\`\`\`rust
use tokio_tungstenite::{connect_async, tungstenite::Message};
use serde_json::{json, Value};
use uuid::Uuid;
use std::collections::HashMap;

pub struct AsyncAPIClient {
    ws_stream: Option<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    pending_requests: HashMap<String, tokio::sync::oneshot::Sender<Value>>,
}

impl AsyncAPIClient {
    pub async fn connect(url: &str, token: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Create connection with authentication header
        let mut request = url.into_client_request()?;
        request.headers_mut().insert(
            "Authorization",
            format!("Bearer {}", token).parse()?
        );

        let (ws_stream, _) = connect_async(request).await?;

        Ok(Self {
            ws_stream: Some(ws_stream),
            pending_requests: HashMap::new(),
        })
    }

    pub async fn signup_user(&mut self, user_data: UserSignupRequest) -> Result<UserWelcomeResponse, Box<dyn std::error::Error>> {
        let correlation_id = Uuid::new_v4().to_string();

        let message = json!({
            "channel": "/ws/user/signup",
            "operation": "handleUserSignup",
            "correlationId": correlation_id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "payload": user_data
        });

        // Send request and wait for response
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending_requests.insert(correlation_id.clone(), tx);

        if let Some(ws) = &mut self.ws_stream {
            ws.send(Message::Text(message.to_string())).await?;
        }

        // Wait for response with timeout
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            rx
        ).await??;

        Ok(serde_json::from_value(response)?)
    }
}
\`\`\`

### Authentication and Security

#### JWT Token Authentication

\`\`\`rust
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};

// In your WebSocket handler
pub async fn authenticate_websocket_connection(
    headers: &HeaderMap,
) -> Result<Claims, AuthError> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(AuthError::MissingToken)?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AuthError::InvalidFormat);
    }

    let token = &auth_header[7..]; // Remove "Bearer " prefix

    let validation = Validation::new(Algorithm::HS256);
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &validation,
    )?;

    Ok(token_data.claims)
}

// Include claims in message context for authorization
impl MessageContext {
    pub fn with_auth_claims(mut self, claims: Claims) -> Self {
        self.claims = Some(claims);
        self
    }
}
\`\`\`

### Error Handling and Reconnection

\`\`\`rust
// Implement robust error handling for WebSocket connections
impl WebSocketTransport {
    async fn handle_connection_error(&mut self, error: &WebSocketError) -> AsyncApiResult<()> {
        match error {
            WebSocketError::ConnectionClosed => {
                tracing::warn!("WebSocket connection closed, attempting reconnection");
                self.reconnect_with_backoff().await?;
            }
            WebSocketError::Timeout => {
                tracing::warn!("WebSocket operation timed out");
                // Implement timeout handling
            }
            WebSocketError::AuthenticationFailed => {
                tracing::error!("WebSocket authentication failed");
                return Err(AsyncApiError::Authentication("Invalid credentials".into()));
            }
            _ => {
                tracing::error!("Unexpected WebSocket error: {}", error);
            }
        }
        Ok(())
    }

    async fn reconnect_with_backoff(&mut self) -> AsyncApiResult<()> {
        let mut delay = Duration::from_millis(100);
        let max_delay = Duration::from_secs(30);
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 5;

        while attempts < MAX_ATTEMPTS {
            tokio::time::sleep(delay).await;

            match self.connect().await {
                Ok(()) => {
                    tracing::info!("WebSocket reconnected successfully after {} attempts", attempts + 1);
                    return Ok(());
                }
                Err(e) => {
                    attempts += 1;
                    delay = std::cmp::min(delay * 2, max_delay);
                    tracing::warn!("Reconnection attempt {} failed: {}", attempts, e);
                }
            }
        }

        Err(AsyncApiError::Connection("Failed to reconnect after maximum attempts".into()))
    }
}
\`\`\`

### Monitoring and Observability

\`\`\`rust
// Add comprehensive metrics for WebSocket operations
use prometheus::{Counter, Histogram, Gauge};

lazy_static! {
    static ref WS_CONNECTIONS: Gauge = Gauge::new(
        "websocket_active_connections",
        "Number of active WebSocket connections"
    ).unwrap();

    static ref WS_MESSAGES_SENT: Counter = Counter::new(
        "websocket_messages_sent_total",
        "Total number of WebSocket messages sent"
    ).unwrap();

    static ref WS_REQUEST_DURATION: Histogram = Histogram::new(
        "websocket_request_duration_seconds",
        "WebSocket request processing duration"
    ).unwrap();
}

// Track metrics in your handlers
impl WebSocketTransport {
    async fn send_message(&mut self, message: TransportMessage) -> AsyncApiResult<()> {
        let _timer = WS_REQUEST_DURATION.start_timer();

        // Send message logic here

        WS_MESSAGES_SENT.inc();
        Ok(())
    }
}
\`\`\`

## Generated Code Structure

The template generates the following key components:

### 1. Strongly Typed Models (\`src/models.rs\`)

${messageArray.map(message => {
        const messageName = pascalCase(message.name());
        const schema = message.payload();

        return `\`\`\`rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ${messageName} {
${schema && schema.properties() ? Object.entries(schema.properties()).map(([key, prop]) => {
          const rustType = (() => {
            const type = prop.type();
            const format = prop.format();

            if (type === 'string') {
              if (format === 'uuid') return 'uuid::Uuid';
              if (format === 'date-time') return 'chrono::DateTime<chrono::Utc>';
              return 'String';
            }
            if (type === 'integer') return 'i64';
            if (type === 'number') return 'f64';
            if (type === 'boolean') return 'bool';
            if (type === 'array') return 'Vec<String>'; // Simplified
            return 'serde_json::Value';
          })();

          const requiredFields = schema.required && (typeof schema.required === 'function' ? schema.required() : schema.required);
          const isRequired = requiredFields && Array.isArray(requiredFields) && requiredFields.indexOf(key) !== -1;
          const finalType = isRequired ? rustType : `Option<${rustType}>`;

          return `    pub ${camelCase(key)}: ${finalType},`;
        }).join('\n') : '    pub data: serde_json::Value,'}
}
\`\`\``;
      }).join('\n\n')}

### 2. Service Traits (\`src/handlers.rs\`)

The generated service traits use strongly-typed request/response patterns:

\`\`\`rust
#[async_trait]
pub trait UserSignupService: Send + Sync {
    /// Handle handleUserSignup request and return response
    /// The response will be automatically sent back via the transport layer
    async fn handle_handle_user_signup(
        &self,
        request: UserSignup,
        context: &MessageContext,
    ) -> AsyncApiResult<UserWelcome>;
}
\`\`\`

Note: The method names use snake_case (e.g., \`handle_handle_user_signup\`) and for request/response patterns, the method returns the strongly-typed response which is automatically sent back via the transport layer.

## Basic Usage

### 1. Implement Your Service Logic

\`\`\`rust
use async_trait::async_trait;
use crate::handlers::{UserSignupService, MessageContext};
use crate::models::*;
use crate::errors::AsyncApiResult;
use std::sync::Arc;

pub struct MyUserService {
    // Your service dependencies here
}

#[async_trait]
impl UserSignupService for MyUserService {
    async fn handle_handle_user_signup(
        &self,
        request: UserSignup,
        context: &MessageContext,
    ) -> AsyncApiResult<UserWelcome> {
        println!("Processing user signup: {:?}", request);

        // Your business logic here
        // For example: validate user data, create account, send welcome email

        // Return the welcome response (automatically sent back)
        let response = UserWelcome {
            user_id: request.id,
            message: format!("Welcome {}! Your account has been created.", request.username),
            resources: Some(vec![
                "https://docs.example.com/getting-started".to_string(),
                "https://support.example.com".to_string(),
            ]),
        };

        Ok(response)
    }
}
\`\`\`

### 2. Setup and Start the Server

\`\`\`rust
use std::sync::Arc;
use crate::{
    handlers::{${channelArray.map(ch => pascalCase(ch.id()) + 'Handler').join(', ')}, MessageContext},
    transport::TransportManager,
    recovery::RecoveryManager,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::init();

    // Create service implementation
    let service = Arc::new(MyUserService {});

    // Create managers
    let recovery_manager = Arc::new(RecoveryManager::default());
    let transport_manager = Arc::new(TransportManager::new());

${channelArray.map(channel => {
        const channelName = pascalCase(channel.id());
        const handlerName = `${channelName}Handler`;
        const varName = camelCase(channelName + 'Handler');

        return `    // Create ${channelName} handler
    let ${varName} = Arc::new(${handlerName}::new(
        service.clone(),
        recovery_manager.clone(),
        transport_manager.clone(),
    ));

    // Register ${channelName} handler
    transport_manager.register_handler(
        "${channel.id()}".to_string(),
        ${varName},
    ).await?;`;
      }).join('\n\n')}

    // Start listening for messages
    transport_manager.start().await?;

    Ok(())
}
\`\`\`

### 3. Sending Messages

You can also send messages using the generated handlers:

\`\`\`rust
use crate::models::*;
use uuid::Uuid;
use chrono::Utc;

${messageArray.slice(0, 1).map(message => {
        const messageName = pascalCase(message.name());
        const schema = message.payload();

        return `// Create a ${messageName} message
let message = ${messageName} {
${schema && schema.properties() ? Object.entries(schema.properties()).slice(0, 3).map(([key, prop]) => {
          const type = prop.type();
          const format = prop.format();

          let value;
          if (type === 'string') {
            if (format === 'uuid') value = 'Uuid::new_v4()';
            else if (format === 'date-time') value = 'Utc::now()';
            else value = `"example ${key}".to_string()`;
          } else if (type === 'integer' || type === 'number') {
            value = '42';
          } else if (type === 'boolean') {
            value = 'true';
          } else if (type === 'array') {
            value = 'vec![]';
          } else {
            value = 'Default::default()';
          }

          return `    ${camelCase(key)}: ${value},`;
        }).join('\n') : '    data: serde_json::json!({}),'}
};

// Create message context
let context = MessageContext::new("${channelArray[0] ? channelArray[0].id() : 'channel'}", "${operationArray[0] ? operationArray[0].id() : 'operation'}");

// Send the message (example)
// handler.send_message(message, &context).await?;`;
      }).join('\n')}
\`\`\`

## Request/Response Flow

The architecture works as follows:

1. **Message Arrives**: Transport receives a message with channel and operation metadata
2. **Handler Routing**: TransportManager routes to the appropriate channel handler
3. **Service Processing**: Handler calls your service implementation with strongly-typed data
4. **Response**: Service processes the message and can send responses if needed

### Example Message Flow

\`\`\`
Incoming Message → TransportManager → ${channelArray[0] ? pascalCase(channelArray[0].id()) + 'Handler' : 'Handler'} → MyService::handle_${operationArray[0] ? camelCase(operationArray[0].id()) : 'operation'}()
\`\`\`

## Error Handling and Recovery

The RecoveryManager automatically handles:

- **Retries**: Failed messages are automatically retried with exponential backoff
- **Circuit Breaker**: Failing services are temporarily isolated
- **Dead Letter Queue**: Unprocessable messages are stored for later analysis

\`\`\`rust
// Messages that fail processing are automatically handled:
// 1. Retry with exponential backoff (3 attempts by default)
// 2. If still failing, move to dead letter queue
// 3. Circuit breaker prevents cascading failures
\`\`\`

## Testing Your Service

\`\`\`rust
#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_message_handler() {
        let service = MyService {};

${messageArray.slice(0, 1).map(message => {
        const messageName = pascalCase(message.name());
        const schema = message.payload();

        return `        let test_message = ${messageName} {
${schema && schema.properties() ? Object.entries(schema.properties()).slice(0, 2).map(([key, prop]) => {
          const type = prop.type();
          const format = prop.format();

          let value;
          if (type === 'string') {
            if (format === 'uuid') value = 'Uuid::new_v4()';
            else value = `"test ${key}".to_string()`;
          } else if (type === 'integer' || type === 'number') {
            value = '1';
          } else if (type === 'boolean') {
            value = 'false';
          } else {
            value = 'None';
          }

          return `            ${camelCase(key)}: ${value},`;
        }).join('\n') : '            data: serde_json::json!({"test": "data"}),'}
        };

        let context = MessageContext::new("test_channel", "test_operation");

        // Test your service method here
        // let result = service.handle_operation(test_message, &context).await;
        // assert!(result.is_ok());`;
      }).join('\n')}
    }
}
\`\`\`

## Key Benefits

1. **Strongly Typed**: All messages are generated from AsyncAPI schemas with full type safety
2. **Simple Architecture**: Clean separation between transport, handlers, and business logic
3. **Automatic Recovery**: Built-in retry logic, circuit breakers, and error handling
4. **Transport Agnostic**: Same code works with HTTP, MQTT, Kafka, etc.
5. **Easy Testing**: Clean service interfaces make unit testing straightforward
6. **AsyncAPI Compliant**: Generated code matches your AsyncAPI specification exactly

This approach provides a clean, performant, and maintainable way to build AsyncAPI services in Rust!
`}
    </File>
  );
};
