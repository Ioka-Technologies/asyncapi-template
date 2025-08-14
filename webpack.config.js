const path = require('path');

// Get all template directories
const templateDirs = ['rust-client', 'rust-server', 'ts-client'];

// Create webpack configurations for each template
const configs = templateDirs.map(templateDir => {
    const templatePath = path.resolve(__dirname, templateDir);
    const distPath = path.resolve(templatePath, 'dist');

    return {
        name: templateDir,
        mode: 'production',
        target: 'node',
        entry: {
            // Bundle the common utilities
            'common/index': path.resolve(__dirname, 'common/src/index.js')
        },
        output: {
            path: distPath,
            filename: '[name].js',
            library: {
                type: 'module'
            },
            clean: false  // Don't clean to preserve template files
        },
        experiments: {
            outputModule: true
        },
        resolve: {
            extensions: ['.js', '.json'],
            alias: {
                '@common': path.resolve(__dirname, 'common/src')
            }
        },
        module: {
            rules: [
                {
                    test: /\.js$/,
                    exclude: /node_modules/,
                    use: {
                        loader: 'babel-loader',
                        options: {
                            presets: [
                                ['@babel/preset-env', {
                                    targets: { node: '16' },
                                    modules: false
                                }]
                            ]
                        }
                    }
                }
            ]
        },
        optimization: {
            minimize: false, // Keep readable for debugging
            usedExports: true,
            sideEffects: false
        },
        externals: {
            // Don't bundle AsyncAPI generator SDK
            '@asyncapi/generator-react-sdk': '@asyncapi/generator-react-sdk'
        }
    };
});

module.exports = configs;
