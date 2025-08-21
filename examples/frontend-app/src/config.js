// Configuration file that nginx handles specially
// This demonstrates the config.js location block in default.conf
window.APP_CONFIG = {
    apiUrl: '/api',
    appName: 'Aquia Frontend Example',
    version: '1.0.0',
    environment: 'production',
    features: {
        nonce: 'FAKE_NONCE', // This will be replaced by nginx sub_filter
        gzipEnabled: true,
        healthCheck: '/nginx_status'
    }
};

console.log('App config loaded:', window.APP_CONFIG);