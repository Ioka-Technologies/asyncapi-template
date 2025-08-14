#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

    // 2. Create production versions of files that import from common
    const updateImportsInDirectory = (dirPath, relativePath = '') => {
        if (!fs.existsSync(dirPath)) return;

        const items = fs.readdirSync(dirPath);

        items.forEach(item => {
            const itemPath = path.join(dirPath, item);
            const stat = fs.statSync(itemPath);

            if (stat.isDirectory()) {
                updateImportsInDirectory(itemPath, path.join(relativePath, item));
            } else if (item.endsWith('.js')) {
                const content = fs.readFileSync(itemPath, 'utf8');

                // Replace development imports with production imports
                let productionContent = content;

                // For files in template/src/ - they need to go up 2 levels to reach dist/
                productionContent = productionContent.replace(
                    /from\s+['"]\.\.\/\.\.\/\.\.\/common\/src\/index\.js['"];?/g,
                    'from "../../dist/common/index.js";'
                );

                // For files in template/helpers/ - they need to go up 1 level to reach dist/
                // This handles cases where the path was already updated to ../dist/common/index.js
                productionContent = productionContent.replace(
                    /from\s+['"]\.\.\/dist\/common\/index\.js['"];?/g,
                    'from "../dist/common/index.js";'
                );

                if (content !== productionContent) {
                    // Create backup of original
                    fs.writeFileSync(itemPath + '.dev', content);
                    // Write production version
                    fs.writeFileSync(itemPath, productionContent);
                    const relativeFilePath = path.join(relativePath, item);
                    console.log(`  📝 Updated ${relativeFilePath} for production`);
                }
            }
        });
    };

    // Update imports in template directory recursively
    const templateDirPath = path.join(templatePath, 'template');
    updateImportsInDirectory(templateDirPath);

    console.log(`  ✅ ${templateDir} ready for publishing\n`);
});

console.log('🎉 All templates built for npm publishing!');
console.log('\n📋 Next steps:');
console.log('1. Test the templates to ensure they work with bundled imports');
console.log('2. Publish to npm');
console.log('3. Run `npm run restore-dev` to restore development imports');
