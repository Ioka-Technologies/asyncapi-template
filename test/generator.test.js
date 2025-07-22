/* eslint-disable no-undef */
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

describe('AsyncAPI Rust Template Generator', () => {
    const outputDir = path.join(__dirname, 'output');

    beforeAll(() => {
        // Clean up any existing output
        if (fs.existsSync(outputDir)) {
            fs.rmSync(outputDir, { recursive: true, force: true });
        }
    });

    afterAll(() => {
        // Clean up test output
        if (fs.existsSync(outputDir)) {
            fs.rmSync(outputDir, { recursive: true, force: true });
        }
    });

    describe('MQTT Template Generation', () => {
        const mqttOutputDir = path.join(outputDir, 'mqtt');

        test('should generate MQTT server from fixture', () => {
            const fixtureFile = path.join(__dirname, 'fixtures', 'mqtt.yaml');
            const templateDir = path.join(__dirname, '..');

            expect(fs.existsSync(fixtureFile)).toBe(true);

            // Generate using AsyncAPI CLI
            const command = `npx @asyncapi/cli generate fromTemplate ${fixtureFile} ${templateDir} --output ${mqttOutputDir} --force-write`;

            expect(() => {
                execSync(command, { stdio: 'inherit' });
            }).not.toThrow();
        });

        test('should generate required Rust files', () => {
            const expectedFiles = [
                'Cargo.toml',
                'README.md',
                'src/main.rs',
                'src/config.rs',
                'src/errors.rs',
                'src/handlers.rs',
                'src/middleware.rs',
                'src/models.rs',
                'src/recovery.rs',
                'src/server/mod.rs'
            ];

            expectedFiles.forEach(file => {
                const filePath = path.join(mqttOutputDir, file);
                expect(fs.existsSync(filePath)).toBe(true);
            });
        });

        test('generated Cargo.toml should be valid', () => {
            const cargoTomlPath = path.join(mqttOutputDir, 'Cargo.toml');
            const content = fs.readFileSync(cargoTomlPath, 'utf8');

            expect(content).toContain('[package]');
            expect(content).toContain('name = "mqtt-user-service"');
            expect(content).toContain('[dependencies]');
            expect(content).toContain('tokio');
            expect(content).toContain('serde');
        });

        test('generated models should contain message types', () => {
            const modelsPath = path.join(mqttOutputDir, 'src', 'models.rs');
            const content = fs.readFileSync(modelsPath, 'utf8');

            // Check for generated message structs (using generic names for now)
            expect(content).toContain('pub struct Item0');
            expect(content).toContain('pub struct Item1');
            expect(content).toContain('pub struct Item2');
            expect(content).toContain('pub struct Item3');
            expect(content).toContain('AsyncApiMessage');
        });

        test('generated code should compile', () => {
            const command = `cd ${mqttOutputDir} && cargo check`;

            expect(() => {
                execSync(command, { stdio: 'inherit' });
            }).not.toThrow();
        }, 30000); // 30 second timeout for compilation
    });

    describe('Kafka Template Generation', () => {
        const kafkaOutputDir = path.join(outputDir, 'kafka');

        test('should generate Kafka server from fixture', () => {
            const fixtureFile = path.join(__dirname, 'fixtures', 'kafka.yaml');
            const templateDir = path.join(__dirname, '..');

            expect(fs.existsSync(fixtureFile)).toBe(true);

            const command = `npx @asyncapi/cli generate fromTemplate ${fixtureFile} ${templateDir} --output ${kafkaOutputDir} --force-write`;

            expect(() => {
                execSync(command, { stdio: 'inherit' });
            }).not.toThrow();
        });

        test('should generate Kafka-specific configuration', () => {
            const cargoTomlPath = path.join(kafkaOutputDir, 'Cargo.toml');
            const content = fs.readFileSync(cargoTomlPath, 'utf8');

            // Check that the package name is generated from the title
            expect(content).toContain('name = "kafka-order-processing-service"');
            expect(content).toContain('rdkafka');
        });

        test('generated models should contain Kafka message types', () => {
            const modelsPath = path.join(kafkaOutputDir, 'src', 'models.rs');
            const content = fs.readFileSync(modelsPath, 'utf8');

            // Check for generated message structs (using generic names for now)
            expect(content).toContain('pub struct Item0');
            expect(content).toContain('pub struct Item1');
            expect(content).toContain('pub struct Item2');
            expect(content).toContain('pub struct Item3');
            expect(content).toContain('AsyncApiMessage');
        });
    });

    describe('AMQP Template Generation', () => {
        const amqpOutputDir = path.join(outputDir, 'amqp');

        test('should generate AMQP server from fixture', () => {
            const fixtureFile = path.join(__dirname, 'fixtures', 'amqp.yaml');
            const templateDir = path.join(__dirname, '..');

            expect(fs.existsSync(fixtureFile)).toBe(true);

            const command = `npx @asyncapi/cli generate fromTemplate ${fixtureFile} ${templateDir} --output ${amqpOutputDir} --force-write`;

            expect(() => {
                execSync(command, { stdio: 'inherit' });
            }).not.toThrow();
        });

        test('should generate AMQP-specific configuration', () => {
            const cargoTomlPath = path.join(amqpOutputDir, 'Cargo.toml');
            const content = fs.readFileSync(cargoTomlPath, 'utf8');

            expect(content).toContain('name = "amqp-notification-service"');
            expect(content).toContain('lapin');
        });

        test('generated models should contain AMQP message types', () => {
            const modelsPath = path.join(amqpOutputDir, 'src', 'models.rs');
            const content = fs.readFileSync(modelsPath, 'utf8');

            // Check for generated message structs (using generic names for now)
            expect(content).toContain('pub struct Item0');
            expect(content).toContain('pub struct Item1');
            expect(content).toContain('pub struct Item2');
            expect(content).toContain('pub struct Item3');
            expect(content).toContain('pub struct Item4');
            expect(content).toContain('AsyncApiMessage');
        });
    });

    describe('Template Parameters', () => {
        test('should respect packageName parameter', () => {
            const fixtureFile = path.join(__dirname, 'fixtures', 'mqtt.yaml');
            const templateDir = path.join(__dirname, '..');
            const customOutputDir = path.join(outputDir, 'custom-name');

            const command = `npx @asyncapi/cli generate fromTemplate ${fixtureFile} ${templateDir} --output ${customOutputDir} --param packageName=my-custom-server --force-write`;

            expect(() => {
                execSync(command, { stdio: 'inherit' });
            }).not.toThrow();

            const cargoTomlPath = path.join(customOutputDir, 'Cargo.toml');
            const content = fs.readFileSync(cargoTomlPath, 'utf8');

            expect(content).toContain('name = "my-custom-server"');
        });

        test('should respect useAsyncStd parameter', () => {
            const fixtureFile = path.join(__dirname, 'fixtures', 'mqtt.yaml');
            const templateDir = path.join(__dirname, '..');
            const asyncStdOutputDir = path.join(outputDir, 'async-std');

            const command = `npx @asyncapi/cli generate fromTemplate ${fixtureFile} ${templateDir} --output ${asyncStdOutputDir} --param useAsyncStd=true --force-write`;

            expect(() => {
                execSync(command, { stdio: 'inherit' });
            }).not.toThrow();

            const cargoTomlPath = path.join(asyncStdOutputDir, 'Cargo.toml');
            const content = fs.readFileSync(cargoTomlPath, 'utf8');

            expect(content).toContain('async-std');
            expect(content).not.toContain('tokio');
        });
    });

    describe('Generated Documentation', () => {
        test('should generate comprehensive README', () => {
            const mqttOutputDir = path.join(outputDir, 'mqtt');
            const readmePath = path.join(mqttOutputDir, 'README.md');

            if (fs.existsSync(readmePath)) {
                const content = fs.readFileSync(readmePath, 'utf8');

                expect(content).toContain('# MQTT User Service');
                expect(content).toContain('## Features');
                expect(content).toContain('## Usage');
                expect(content).toContain('## Configuration');
            }
        });
    });
});
