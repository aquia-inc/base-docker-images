// Simple frontend app that demonstrates the nginx configuration
document.addEventListener('DOMContentLoaded', function() {
    const statusElement = document.getElementById('status');
    
    // Simulate app initialization
    setTimeout(() => {
        statusElement.innerHTML = `
            <p><strong>✅ App Status: Loaded</strong></p>
            <p>Served by nginx-base on port 8080</p>
            <p>Built with nodejs-base build tools</p>
            <small>Request ID: ${Math.random().toString(36).substr(2, 9)}</small>
        `;
        statusElement.className = 'status loaded';
    }, 1000);
    
    // Test the nonce replacement from nginx config
    console.log('FAKE_NONCE should be replaced by nginx sub_filter');
    
    // Basic client-side routing simulation for SPA
    window.addEventListener('popstate', function(event) {
        console.log('Route changed - nginx try_files handles fallback');
    });
});