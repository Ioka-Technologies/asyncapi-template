#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const templateDirs = ['rust-client', 'rust-server', 'ts-client'];

console.log('🔄 Restoring development imports...\n');

templateDirs.forEach(templateDir => {
    console.log(`📦 Processing ${templateDir}...`);

    const templatePath = path.resolve(__dirname, '..', templateDir);
    const helpersPath = path.join(templatePath, 'template', 'helpers');

    if (fs.existsSync(helpersPath)) {
        const helperFiles = fs.readdirSync(helpersPath).filter(f => f.endsWith('.js.dev'));

        helperFiles.forEach(backupFile => {
            const originalFile = backupFile.replace('.dev', '');
            const backupFilePath = path.join(helpersPath, backupFile);
            const originalFilePath = path.join(helpersPath, originalFile);

            if (fs.existsSync(backupFilePath)) {
                // Restore original development version
                const devContent = fs.readFileSync(backupFilePath, 'utf8');
                fs.writeFileSync(originalFilePath, devContent);
                // Remove backup
                fs.unlinkSync(backupFilePath);
                console.log(`  📝 Restored ${originalFile} to development version`);
            }
        });
    }

    console.log(`  ✅ ${templateDir} restored to development mode\n`);
});

console.log('🎉 All templates restored to development imports!');
