#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const templateDirs = ['rust-client', 'rust-server', 'ts-client'];

console.log('🧪 Testing templates as if they were published to npm...\n');

async function testTemplate(templateDir) {
    console.log(`📦 Testing ${templateDir}...`);

    const templatePath = path.resolve(__dirname, '..', templateDir);
    const testDir = path.join(templatePath, 'test-published');

    try {
        // 1. Create a test directory
        if (fs.existsSync(testDir)) {
            execSync(`rm -rf ${testDir}`, { cwd: templatePath });
        }
        fs.mkdirSync(testDir, { recursive: true });

        // 2. Pack the template as if publishing to npm
        console.log(`  📦 Packing ${templateDir} template...`);
        const packResult = execSync('npm pack', {
            cwd: templatePath,
            encoding: 'utf8'
        });

        const tarballName = packResult.trim().split('\n').pop();

        // 3. Extract the tarball to simulate npm install
        console.log(`  📂 Extracting ${tarballName}...`);
        execSync(`tar -xzf ${tarballName} -C ${testDir}`, { cwd: templatePath });

        // 4. Test the extracted template
        const extractedPath = path.join(testDir, 'package');
        console.log('  🧪 Testing extracted template...');

        // Choose appropriate example based on template
        let examplePath, outputDir, testCommand;

        if (templateDir === 'rust-client') {
            // Copy the NATS example to the test directory
            const sourceExample = path.resolve(__dirname, '..', 'examples', 'nats', 'asyncapi.yaml');
            const targetExample = path.join(extractedPath, 'nats-example.yaml');
            fs.copyFileSync(sourceExample, targetExample);
            examplePath = 'nats-example.yaml';
            outputDir = 'test-nats-output';
            testCommand = 'cargo build --lib';
        } else if (templateDir === 'rust-server') {
            // Copy the simple example to the test directory
            const sourceExample = path.resolve(__dirname, '..', 'examples', 'simple', 'asyncapi.yaml');
            const targetExample = path.join(extractedPath, 'simple-example.yaml');
            fs.copyFileSync(sourceExample, targetExample);
            examplePath = 'simple-example.yaml';
            outputDir = 'test-simple-output';
            testCommand = 'cargo build --lib';
        } else if (templateDir === 'ts-client') {
            // ts-client includes its own examples
            examplePath = 'examples/simple/asyncapi.yaml';
            outputDir = 'test-simple-output';
            testCommand = 'npm install && npm run build';
        }

        // 5. Generate from the extracted template
        const generateCommand = `npx @asyncapi/cli generate fromTemplate ${examplePath} ./ -o ${outputDir} --force-write`;
        console.log(`  🔧 Running: ${generateCommand}`);

        execSync(generateCommand, {
            cwd: extractedPath,
            stdio: 'inherit'
        });

        // 6. Test the generated code
        if (testCommand) {
            console.log(`  🔨 Testing generated code: ${testCommand}`);
            execSync(testCommand, {
                cwd: path.join(extractedPath, outputDir),
                stdio: 'inherit'
            });
        }

        // 7. Cleanup
        execSync(`rm -f ${tarballName}`, { cwd: templatePath });
        execSync(`rm -rf ${testDir}`, { cwd: templatePath });

        console.log(`  ✅ ${templateDir} published package test PASSED\n`);
        return true;

    } catch (error) {
        console.error(`  ❌ ${templateDir} published package test FAILED:`);
        console.error(`     ${error.message}\n`);

        // Cleanup on failure
        try {
            execSync(`rm -rf ${testDir}`, { cwd: templatePath });
            const files = fs.readdirSync(templatePath);
            const tarball = files.find(f => f.endsWith('.tgz'));
            if (tarball) {
                execSync(`rm -f ${tarball}`, { cwd: templatePath });
            }
        } catch (cleanupError) {
            // Ignore cleanup errors
        }

        return false;
    }
}

async function runTests() {
    let allPassed = true;

    for (const templateDir of templateDirs) {
        const passed = await testTemplate(templateDir);
        if (!passed) {
            allPassed = false;
        }
    }

    if (allPassed) {
        console.log('🎉 All published package tests PASSED!');
        console.log('✅ Templates are ready for npm publishing.');
        process.exit(0);
    } else {
        console.log('❌ Some published package tests FAILED!');
        console.log('🔧 Please fix the issues before publishing.');
        process.exit(1);
    }
}

runTests().catch(error => {
    console.error('💥 Test runner failed:', error);
    process.exit(1);
});
