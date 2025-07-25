//! Example demonstrating MessageEnvelope usage
//!
//! This example shows how to create, send, and handle messages using the MessageEnvelope
//! pattern for better correlation, error handling, and observability.

use chrono::Utc;
use serde_json;
use uuid::Uuid;

// Import the generated models
use simple_user_service::models::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== MessageEnvelope Example ===\n");

    // 1. Create a UserSignup payload
    let user_signup = UserSignup {
        id: Uuid::new_v4(),
        username: "alice".to_string(),
        email: "alice@example.com".to_string(),
        full_name: Some("Alice Johnson".to_string()),
        created_at: Utc::now(),
        preferences: Some(UserSignupPreferences {
            newsletter: Some(true),
            notifications: Some(true),
            theme: Some(UserSignupPreferencesThemeEnum::Dark),
            language: Some("en".to_string()),
        }),
    };

    println!("1. Created UserSignup:");
    println!("   - User ID: {}", user_signup.id);
    println!("   - Username: {}", user_signup.username);
    println!("   - Email: {}", user_signup.email);
    println!();

    // 2. Create a MessageEnvelope for the request
    let request_envelope = MessageEnvelope::new_with_id("handleUserSignup", &user_signup)?
        .with_channel("userSignup".to_string());

    println!("2. Created MessageEnvelope:");
    println!("   - Operation: {}", request_envelope.operation);
    println!("   - Correlation ID: {:?}", request_envelope.id);
    println!("   - Channel: {:?}", request_envelope.channel);
    println!("   - Timestamp: {:?}", request_envelope.timestamp);
    println!();

    // 3. Serialize the envelope (this is what would be sent over the wire)
    let serialized_envelope = serde_json::to_string_pretty(&request_envelope)?;
    println!("3. Serialized MessageEnvelope:");
    println!("{}", serialized_envelope);
    println!();

    // 4. Demonstrate extracting the payload back
    let extracted_message: UserSignup = request_envelope.extract_payload()?;
    println!("4. Extracted UserSignup from envelope:");
    println!("   - User ID: {}", extracted_message.id);
    println!("   - Username: {}", extracted_message.username);
    println!("   - Email: {}", extracted_message.email);
    println!();

    // 5. Create a response envelope
    let response_payload = UserWelcome {
        user_id: user_signup.id,
        message: format!("Welcome to our service, {}!", user_signup.username),
        resources: Some(vec![
            "Getting Started Guide".to_string(),
            "User Manual".to_string(),
            "Support Portal".to_string(),
        ]),
    };

    let response_envelope =
        request_envelope.create_response("handleUserSignup_response", &response_payload)?;

    println!("5. Created response envelope:");
    println!("   - Operation: {}", response_envelope.operation);
    println!("   - Correlation ID: {:?}", response_envelope.id);
    println!(
        "   - Same correlation ID: {}",
        request_envelope.id == response_envelope.id
    );
    println!();

    // 6. Demonstrate error response
    let error_envelope = MessageEnvelope::error_response(
        "handleUserSignup_response",
        "VALIDATION_ERROR",
        "Email address is already in use",
        request_envelope.id.clone(),
    );

    println!("6. Created error response envelope:");
    println!("   - Operation: {}", error_envelope.operation);
    println!(
        "   - Error code: {:?}",
        error_envelope.error.as_ref().map(|e| &e.code)
    );
    println!(
        "   - Error message: {:?}",
        error_envelope.error.as_ref().map(|e| &e.message)
    );
    println!("   - Is error: {}", error_envelope.is_error());
    println!();

    // 7. Demonstrate envelope utilities
    println!("7. Envelope utilities:");
    println!(
        "   - Request correlation ID: {:?}",
        request_envelope.correlation_id()
    );
    println!(
        "   - Response correlation ID: {:?}",
        response_envelope.correlation_id()
    );
    println!(
        "   - Error correlation ID: {:?}",
        error_envelope.correlation_id()
    );
    println!("   - Request is error: {}", request_envelope.is_error());
    println!("   - Response is error: {}", response_envelope.is_error());
    println!("   - Error is error: {}", error_envelope.is_error());
    println!();

    // 8. Show how this integrates with the handler pattern
    println!("8. Handler Integration:");
    println!("   In the generated handlers, messages are automatically:");
    println!("   - Parsed from MessageEnvelope format");
    println!("   - Validated for structure and content");
    println!("   - Processed by your business logic");
    println!("   - Wrapped in response envelopes");
    println!("   - Sent back with proper correlation IDs");
    println!();

    println!("=== Example Complete ===");

    Ok(())
}
