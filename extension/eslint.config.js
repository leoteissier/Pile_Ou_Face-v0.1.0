import js from '@eslint/js';
import prettier from 'eslint-config-prettier';

export default [
  {
    ignores: ['node_modules/', '.nyc_output/', 'coverage/', '*.vsix', 'webview/media/app/'],
  },
  js.configs.recommended,
  prettier,
  {
    files: ['src/**/*.js'],
    languageOptions: {
      ecmaVersion: 2020,
      sourceType: 'commonjs',
      globals: {
        require: 'readonly',
        module: 'readonly',
        process: 'readonly',
        console: 'readonly',
        Buffer: 'readonly',
      },
    },
    rules: {
      'no-console': 'warn',
      'no-unused-vars': 'off',
      'prefer-const': 'error',
    },
  },
  {
    files: ['test/**/*.js'],
    languageOptions: {
      ecmaVersion: 2020,
      sourceType: 'commonjs',
      globals: {
        require: 'readonly',
        module: 'readonly',
        describe: 'readonly',
        it: 'readonly',
        beforeEach: 'readonly',
        afterEach: 'readonly',
        Buffer: 'readonly',
      },
    },
    rules: {
      'no-unused-vars': 'off',
    },
  },
  {
    files: ['webview/**/*.js'],
    languageOptions: {
      ecmaVersion: 2020,
      sourceType: 'module',
      globals: {
        window: 'readonly',
        document: 'readonly',
        FormData: 'readonly',
        acquireVsCodeApi: 'readonly',
        setTimeout: 'readonly',
        console: 'readonly',
      },
    },
    rules: {
      'no-unused-vars': 'off',
    },
  },
];

