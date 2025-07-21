import { File } from '@asyncapi/generator-react-sdk';

export default function eslintrcFile() {
    return (
        <File name=".eslintrc">
            {`{
  "env": {
    "browser": false,
    "es2021": true,
    "node": true,
    "jest": true
  },
  "extends": [
    "eslint:recommended"
  ],
  "parserOptions": {
    "ecmaVersion": 12,
    "sourceType": "module"
  },
  "plugins": [
    "jest",
    "sonarjs"
  ],
  "rules": {
    "indent": ["error", 4],
    "linebreak-style": ["error", "unix"],
    "quotes": ["error", "single"],
    "semi": ["error", "always"],
    "no-unused-vars": "error",
    "no-console": "warn",
    "sonarjs/cognitive-complexity": ["error", 15],
    "sonarjs/no-duplicate-string": ["error", 3],
    "sonarjs/no-duplicated-branches": "error",
    "sonarjs/no-identical-functions": "error"
  }
}
`}
        </File>
    );
}
