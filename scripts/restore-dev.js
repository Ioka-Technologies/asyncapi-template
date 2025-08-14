#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const templateDirs = ['rust-client', 'rust-server', 'ts-client'];

console.log('🔄 Restoring development imports...\n');

templateDirs.forEach(templateDir => {
    console.log(`📦 Processing ${templateDir}...`);

    const templatePath = path.resolve(__dirname, '..', templateDir);

    const restoreImportsInDirectory = (dirPath, relativePath = '') => {
        if (!fs.existsSync(dirPath)) return;

        const items = fs.readdirSync(dirPath);

        items.forEach(item => {
            const itemPath = path.join(dirPath, item);
            const stat = fs.statSync(itemPath);

            if (stat.isDirectory()) {
                restoreImportsInDirectory(itemPath, path.join(relativePath, item));
            } else if (item.endsWith('.js.dev')) {
                const originalFile = item.replace('.dev', '');
                const backupFilePath = itemPath;
                const originalFilePath = path.join(dirPath, originalFile);

                if (fs.existsSync(backupFilePath)) {
                    // Restore original development version
                    const devContent = fs.readFileSync(backupFilePath, 'utf8');
                    fs.writeFileSync(originalFilePath, devContent);
                    // Remove backup
                    fs.unlinkSync(backupFilePath);
                    const relativeFilePath = path.join(relativePath, originalFile);
                    console.log(`  📝 Restored ${relativeFilePath} to development version`);
                }
            }
        });
    };

    // Restore imports in template directory recursively
    const templateDirPath = path.join(templatePath, 'template');
    restoreImportsInDirectory(templateDirPath);

    console.log(`  ✅ ${templateDir} restored to development mode\n`);
});

console.log('🎉 All templates restored to development imports!');
