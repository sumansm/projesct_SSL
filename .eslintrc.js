module.exports = {
  env: {
    node: true,
    es2021: true,
    browser: true,
  },
  extends: [
    'eslint:recommended',
  ],
  parserOptions: {
    ecmaVersion: 12,
    sourceType: 'module',
  },
  rules: {
    // Error handling
    'no-console': 'warn',
    'no-debugger': 'error',
    
    // Code quality
    'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    'no-undef': 'error',
    'no-redeclare': 'error',
    
    // Best practices
    'eqeqeq': ['error', 'always'],
    'curly': ['error', 'all'],
    'no-eval': 'error',
    'no-implied-eval': 'error',
    'no-new-func': 'error',
    'no-script-url': 'error',
    
    // Styling
    'indent': ['error', 2],
    'quotes': ['error', 'single'],
    'semi': ['error', 'always'],
    'comma-dangle': ['error', 'always-multiline'],
    'no-trailing-spaces': 'error',
    'eol-last': 'error',
    
    // ES6+
    'prefer-const': 'error',
    'no-var': 'error',
    'arrow-spacing': 'error',
    'template-curly-spacing': 'error',
  },
  globals: {
    // jQuery globals
    '$': 'readonly',
    'jQuery': 'readonly',
  },
}; 