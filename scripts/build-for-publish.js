#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const templateDirs = ['rust-client', 'rust-server', 'ts-client'];

console.log('🔧 Building templates for npm publishing...\n');

templateDirs.forEach(templateDir => {
    console.log(`📦 Processing ${templateDir}...`);

    const templatePath = path.resolve(__dirname, '..', templateDir);
    const helpersPath = path.join(templatePath, 'template', 'helpers');

    // 1. First run webpack to create bundled common utilities
    console.log('  ⚙️  Building bundled common utilities...');
    execSync(`webpack --config ../webpack.config.js --env template=${templateDir}`, {
        cwd: templatePath,
        stdio: 'inherit'
    });

    // 2. Create production versions of helper files that import from bundled version
    if (fs.existsSync(helpersPath)) {
        const helperFiles = fs.readdirSync(helpersPath).filter(f => f.endsWith('.js'));

        helperFiles.forEach(helperFile => {
            const helperFilePath = path.join(helpersPath, helperFile);
            const content = fs.readFileSync(helperFilePath, 'utf8');

            // Replace development imports with production imports
            const productionContent = content.replace(
                /from\s+['"]\.\.\/\.\.\/\.\.\/common\/src\/index\.js['"];?/g,
                'from "../dist/common/index.js";'
            );

            if (content !== productionContent) {
                // Create backup of original
                fs.writeFileSync(helperFilePath + '.dev', content);
                // Write production version
                fs.writeFileSync(helperFilePath, productionContent);
                console.log(`  📝 Updated ${helperFile} for production`);
            }
        });
    }

    console.log(`  ✅ ${templateDir} ready for publishing\n`);
});

console.log('🎉 All templates built for npm publishing!');
console.log('\n📋 Next steps:');
console.log('1. Test the templates to ensure they work with bundled imports');
console.log('2. Publish to npm');
console.log('3. Run `npm run restore-dev` to restore development imports');
