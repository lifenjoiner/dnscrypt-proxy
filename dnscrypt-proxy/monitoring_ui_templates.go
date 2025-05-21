package main

// Templates for the monitoring UI

// SimpleHTMLTemplate is the template for the simple monitoring UI
const SimpleHTMLTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>DNSCrypt Proxy Monitoring (Simple)</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body { font-family: sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        table { border-collapse: collapse; width: 100%%; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>DNSCrypt Proxy Monitoring (Simple View)</h1>
    <p>Auto-refreshes every 5 seconds. <a href="/">Switch to full dashboard</a></p>

    <h2>Overview</h2>
    <table>
        <tr><th>Total Queries</th><td>%d</td></tr>
        <tr><th>Queries Per Second</th><td>%.2f</td></tr>
        <tr><th>Uptime</th><td>%.0f seconds</td></tr>
        <tr><th>Cache Hit Ratio</th><td>%.2f%%</td></tr>
        <tr><th>Cache Hits</th><td>%d</td></tr>
        <tr><th>Cache Misses</th><td>%d</td></tr>
    </table>

    <p><small>Generated at %s</small></p>
</body>
</html>`

// MainHTMLTemplate is the template for the main monitoring UI
const MainHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNSCrypt Proxy Monitoring</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 0;
            color: #333;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background-color: #2c3e50;
            color: white;
            padding: 1rem;
            margin-bottom: 20px;
        }
        h1 {
            margin: 0;
            font-size: 1.5rem;
        }
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .card {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            padding: 20px;
        }
        .card h2 {
            margin-top: 0;
            font-size: 1.2rem;
            color: #2c3e50;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        .stat {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }
        .stat-label {
            font-weight: bold;
        }
        .chart-container {
            height: 200px;
            margin-top: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        table th, table td {
            text-align: left;
            padding: 8px;
            border-bottom: 1px solid #eee;
        }
        table th {
            background-color: #f9f9f9;
        }
    </style>
</head>
<body>
    <header>
        <h1>DNSCrypt Proxy Monitoring Dashboard</h1>
        <div style="position: absolute; top: 10px; right: 10px;">
            <a href="/?simple=1" style="color: white; text-decoration: underline; margin-right: 15px;">Simple View</a>
            <a href="/api/metrics" target="_blank" style="color: white; text-decoration: underline;">Raw Data</a>
        </div>
    </header>
    <div class="container">
        <!-- Loading indicator -->
        <div id="loading-indicator" style="text-align: center; padding: 40px; margin: 20px 0; background-color: #f8f9fa; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
            <h2>Loading DNSCrypt Proxy Monitoring...</h2>
            <p>Please wait while we connect to the monitoring service.</p>
            <p>If this message persists, please check that the DNSCrypt Proxy is running with monitoring enabled.</p>
            <div style="margin: 20px 0; height: 4px; background-color: #eee; border-radius: 2px; overflow: hidden;">
                <div id="loading-bar" style="height: 100%; width: 0%; background-color: #2c3e50; animation: loading 2s infinite linear;"></div>
            </div>
            <style>
                @keyframes loading {
                    0% { width: 0%; }
                    50% { width: 100%; }
                    100% { width: 0%; }
                }
            </style>
        </div>

        <div class="dashboard">
            <div class="card">
                <h2>Overview</h2>
                <div class="stat">
                    <span class="stat-label">Total Queries:</span>
                    <span id="total-queries">-</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Queries Per Second:</span>
                    <span id="qps">-</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Uptime:</span>
                    <span id="uptime">-</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Avg Response Time:</span>
                    <span id="avg-response-time">-</span>
                </div>
            </div>
            <div class="card">
                <h2>Cache Performance</h2>
                <div class="stat">
                    <span class="stat-label">Cache Hit Ratio:</span>
                    <span id="cache-hit-ratio">-</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Cache Hits:</span>
                    <span id="cache-hits">-</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Cache Misses:</span>
                    <span id="cache-misses">-</span>
                </div>
                <div class="chart-container" id="cache-chart"></div>
            </div>
            <div class="card">
                <h2>Query Types</h2>
                <div id="query-types-container">
                    <table id="query-types-table">
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Count</th>
                            </tr>
                        </thead>
                        <tbody>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Server Performance</h2>
            <table id="server-table">
                <thead>
                    <tr>
                        <th>Server</th>
                        <th>Queries</th>
                        <th>Avg Response Time</th>
                    </tr>
                </thead>
                <tbody>
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Top Domains</h2>
            <table id="domains-table">
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody>
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Recent Queries</h2>
            <table id="queries-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Domain</th>
                        <th>Type</th>
                        <th>Client</th>
                        <th>Server</th>
                        <th>Response</th>
                        <th>Time (ms)</th>
                    </tr>
                </thead>
                <tbody>
                </tbody>
            </table>
        </div>
    </div>

    <script src="/static/monitoring.js"></script>
</body>
</html>`

// MonitoringJSContent is the JavaScript for the monitoring UI
const MonitoringJSContent = `// Error handling function with fallback to static content
function handleError(error) {
    console.error('Error:', error);
    try {
        // Show error message
        document.getElementById('total-queries').textContent = 'Error loading data';

        // Update the loading indicator with error information
        var loadingIndicator = document.getElementById('loading-indicator');
        if (loadingIndicator) {
            loadingIndicator.style.backgroundColor = '#f8d7da';
            loadingIndicator.style.color = '#721c24';
            loadingIndicator.style.display = 'block';

            loadingIndicator.innerHTML = '<h2>Connection Error</h2>' +
                '<p>Unable to connect to the monitoring server. This could be due to:</p>' +
                '<ul style="text-align: left; display: inline-block;">' +
                '<li>The server is still starting up</li>' +
                '<li>Network connectivity issues</li>' +
                '<li>Server is under heavy load</li>' +
                '</ul>' +
                '<p>The page will automatically retry connecting in 10 seconds.</p>' +
                '<p>You can also try:</p>' +
                '<ul style="text-align: left; display: inline-block;">' +
                '<li>Refreshing the page</li>' +
                '<li>Checking if the DNSCrypt Proxy is running</li>' +
                '<li>Verifying the monitoring UI is enabled in the configuration</li>' +
                '</ul>' +
                '<div style="margin: 20px 0; height: 4px; background-color: #eee; border-radius: 2px; overflow: hidden;">' +
                '<div style="height: 100%; width: 100%; background-color: #dc3545; animation: none;"></div>' +
                '</div>' +
                '<button onclick="window.location.reload()" style="padding: 10px 20px; background-color: #dc3545; color: white; border: none; border-radius: 5px; cursor: pointer;">Retry Now</button>';
        } else {
            // Fallback if loading indicator doesn't exist
            var fallbackDiv = document.createElement('div');
            fallbackDiv.className = 'card';
            fallbackDiv.style.marginTop = '20px';
            fallbackDiv.style.padding = '20px';
            fallbackDiv.style.backgroundColor = '#f8d7da';
            fallbackDiv.style.color = '#721c24';
            fallbackDiv.style.borderRadius = '5px';

            fallbackDiv.innerHTML = '<h3>Connection Error</h3>' +
                '<p>Unable to connect to the monitoring server.</p>' +
                '<p>The page will automatically retry connecting.</p>' +
                '<button onclick="window.location.reload()" style="padding: 10px 20px; background-color: #dc3545; color: white; border: none; border-radius: 5px; cursor: pointer;">Retry Now</button>';

            // Add the fallback message to the page if it doesn't already exist
            if (!document.getElementById('fallback-message')) {
                fallbackDiv.id = 'fallback-message';
                document.querySelector('.container').appendChild(fallbackDiv);
            }
        }

        // Schedule a page reload after 10 seconds
        setTimeout(function() {
            if (!document.hidden) { // Only reload if the page is visible
                console.log('Auto-reloading page after error...');
                window.location.reload();
            }
        }, 10000);
    } catch (e) {
        console.error('Failed to update error message:', e);
    }
}

// Safe update function that handles missing data
function safeUpdateDashboard(data) {
    try {
        if (!data) {
            console.error('No data provided to safeUpdateDashboard');
            return;
        }

        console.log('Updating dashboard with data');

        // Store the current scroll position before updates
        const scrollPos = {
            x: window.scrollX || window.pageXOffset,
            y: window.scrollY || window.pageYOffset
        };

        // Hide loading indicator when data is loaded
        var loadingIndicator = document.getElementById('loading-indicator');
        if (loadingIndicator) {
            loadingIndicator.style.display = 'none';
        }

        // Update overview stats with null checks
        const totalQueries = data.total_queries !== undefined ? data.total_queries : 0;
        const qps = data.queries_per_second !== undefined ? data.queries_per_second : 0;
        const uptime = data.uptime_seconds !== undefined ? data.uptime_seconds : 0;
        const avgResponseTime = data.avg_response_time !== undefined ? data.avg_response_time : 0;

        document.getElementById('total-queries').textContent = totalQueries.toLocaleString();
        document.getElementById('qps').textContent = qps.toFixed(2);
        document.getElementById('uptime').textContent = formatUptime(uptime);
        document.getElementById('avg-response-time').textContent = avgResponseTime.toFixed(2) + ' ms';

        // Update cache stats with null checks
        const cacheHitRatio = data.cache_hit_ratio !== undefined ? data.cache_hit_ratio : 0;
        const cacheHits = data.cache_hits !== undefined ? data.cache_hits : 0;
        const cacheMisses = data.cache_misses !== undefined ? data.cache_misses : 0;

        document.getElementById('cache-hit-ratio').textContent = (cacheHitRatio * 100).toFixed(2) + '%';
        document.getElementById('cache-hits').textContent = cacheHits.toLocaleString();
        document.getElementById('cache-misses').textContent = cacheMisses.toLocaleString();

        // Update server table
        const serverTable = document.getElementById('server-table').getElementsByTagName('tbody')[0];
        serverTable.innerHTML = '';
        if (data.servers && Array.isArray(data.servers)) {
            data.servers.forEach(server => {
                const row = serverTable.insertRow();
                row.insertCell(0).textContent = server.name || 'Unknown';
                row.insertCell(1).textContent = (server.queries || 0).toLocaleString();
                row.insertCell(2).textContent = (server.avg_response_ms || 0).toFixed(2) + ' ms';
            });
        }

        // Update query types table
        const queryTypesTable = document.getElementById('query-types-table').getElementsByTagName('tbody')[0];
        queryTypesTable.innerHTML = '';
        if (data.query_types && Array.isArray(data.query_types)) {
            data.query_types.forEach(type => {
                const row = queryTypesTable.insertRow();
                row.insertCell(0).textContent = type.type || 'Unknown';
                row.insertCell(1).textContent = (type.count || 0).toLocaleString();
            });
        }

        // Update top domains table
        const domainsTable = document.getElementById('domains-table').getElementsByTagName('tbody')[0];
        domainsTable.innerHTML = '';
        if (data.top_domains && Array.isArray(data.top_domains)) {
            data.top_domains.forEach(domain => {
                const row = domainsTable.insertRow();
                row.insertCell(0).textContent = domain.domain || 'Unknown';
                row.insertCell(1).textContent = (domain.count || 0).toLocaleString();
            });
        }

        // Update recent queries table
        const queriesTable = document.getElementById('queries-table').getElementsByTagName('tbody')[0];
        queriesTable.innerHTML = '';
        if (data.recent_queries && Array.isArray(data.recent_queries)) {
            data.recent_queries.slice().reverse().forEach(query => {
                const row = queriesTable.insertRow();
                row.insertCell(0).textContent = query.timestamp ? new Date(query.timestamp).toLocaleTimeString() : '-';
                row.insertCell(1).textContent = query.domain || '-';
                row.insertCell(2).textContent = query.type || '-';
                row.insertCell(3).textContent = query.client_ip || '-';
                row.insertCell(4).textContent = query.server || '-';
                row.insertCell(5).textContent = query.response_code || '-';
                row.insertCell(6).textContent = (query.response_time || 0) + ' ms';
            });
        }

        // Restore scroll position after DOM updates
        window.scrollTo(scrollPos.x, scrollPos.y);
    } catch (error) {
        console.error('Error updating dashboard:', error);
    }
}

function formatUptime(seconds) {
    try {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = Math.floor(seconds % 60);

        let result = '';
        if (days > 0) result += days + 'd ';
        if (hours > 0 || days > 0) result += hours + 'h ';
        if (minutes > 0 || hours > 0 || days > 0) result += minutes + 'm ';
        result += secs + 's';

        return result;
    } catch (error) {
        return 'Error';
    }
}

// Simple direct data loading approach
function loadData() {
    console.log('Loading data using simple approach');

    // Create a script element to load the data
    var script = document.createElement('script');
    script.src = '/api/metrics?callback=handleMetricsData&_=' + new Date().getTime();
    script.onerror = function(e) {
        console.error('Script load error:', e);
        handleError(new Error('Failed to load metrics data'));

        // Try again after 5 seconds
        setTimeout(loadData, 5000);
    };

    // Add the script to the document
    document.body.appendChild(script);

    // Remove the script after a timeout (whether it loaded or not)
    setTimeout(function() {
        if (script.parentNode) {
            script.parentNode.removeChild(script);
        }
    }, 10000);
}

// Callback function for the JSONP-style request
window.handleMetricsData = function(data) {
    console.log('Data received via JSONP');
    if (data) {
        safeUpdateDashboard(data);
    } else {
        console.error('Empty data received');
        handleError(new Error('Empty data received'));
    }
};

// Start loading data
loadData();

// Fallback: If data doesn't load within 10 seconds, try direct XHR
setTimeout(function() {
    var loadingIndicator = document.getElementById('loading-indicator');
    if (loadingIndicator && loadingIndicator.style.display !== 'none') {
        console.log('Loading indicator still visible after 10s, trying direct XHR');

        var xhr = new XMLHttpRequest();
        xhr.open('GET', '/api/metrics', true);
        xhr.timeout = 10000;

        xhr.onload = function() {
            if (xhr.status >= 200 && xhr.status < 300) {
                try {
                    var data = JSON.parse(xhr.responseText);
                    if (data) {
                        console.log('XHR fallback succeeded');
                        safeUpdateDashboard(data);
                    }
                } catch (e) {
                    console.error('XHR fallback parse error:', e);
                }
            }
        };

        xhr.send();
    }
}, 10000);

// WebSocket connection with error handling and reconnection
let wsReconnectAttempts = 0;
const maxReconnectAttempts = 5;
const reconnectDelay = 3000; // 3 seconds

// WebSocket connection with fallback
function connectWebSocket() {
    console.log('Attempting to connect WebSocket...');

    // Check if WebSocket is supported
    if (typeof WebSocket === 'undefined') {
        console.error('WebSocket is not supported in this browser');
        return null;
    }

    try {
        // Construct WebSocket URL
        var protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
        var host = window.location.host;
        var wsUrl = protocol + host + '/api/ws';
        console.log('WebSocket URL:', wsUrl);

        // Create WebSocket connection
        var ws = new WebSocket(wsUrl);

        // Connection opened
        ws.onopen = function() {
            console.log('WebSocket connected successfully');
            wsReconnectAttempts = 0; // Reset reconnect attempts on successful connection

            // Send a ping to verify connection
            try {
                ws.send(JSON.stringify({type: 'ping'}));
            } catch (e) {
                console.error('Error sending ping:', e);
            }
        };

        // Listen for messages
        ws.onmessage = function(event) {
            try {
                if (!event) {
                    console.warn('Received invalid WebSocket event');
                    return;
                }

                if (!event.data) {
                    console.warn('Received empty WebSocket message');
                    return;
                }

                console.log('Received WebSocket data');
                var data = JSON.parse(event.data);
                safeUpdateDashboard(data);
            } catch (error) {
                console.error('Error processing WebSocket data:', error);
            }
        };

        // Handle errors
        ws.onerror = function(error) {
            console.error('WebSocket error occurred:', error);
        };

        // Connection closed
        ws.onclose = function(event) {
            console.log('WebSocket disconnected, code:', event.code, 'reason:', event.reason || 'No reason provided');

            // Try to reconnect with exponential backoff
            if (wsReconnectAttempts < maxReconnectAttempts) {
                wsReconnectAttempts++;
                var delay = reconnectDelay * Math.pow(2, wsReconnectAttempts - 1);
                console.log('Attempting to reconnect in ' + delay + 'ms (attempt ' + wsReconnectAttempts + '/' + maxReconnectAttempts + ')');

                setTimeout(function() {
                    var newWs = connectWebSocket();
                    if (newWs) {
                        // We can't update the global ws variable from here
                        // Instead, we'll rely on the polling fallback
                        console.log('New WebSocket connection established');
                    }
                }, delay);
            } else {
                console.log('Max reconnect attempts reached, falling back to polling');
            }
        };

        return ws;
    } catch (error) {
        console.error('Failed to create WebSocket connection:', error);
        return null;
    }
}

// Start WebSocket connection
let ws = connectWebSocket();

// Polling function with error handling - using script tag approach
function pollMetrics() {
    console.log('Polling metrics...');

    if (!ws || ws.readyState !== WebSocket.OPEN) {
        // Use script tag approach for better compatibility
        var pollScript = document.createElement('script');
        pollScript.src = '/api/metrics?callback=handlePollData&_=' + new Date().getTime();

        // Handle errors
        pollScript.onerror = function(e) {
            console.error('Polling script load error:', e);
        };

        // Add the script to the document
        document.body.appendChild(pollScript);

        // Remove the script after a timeout
        setTimeout(function() {
            if (pollScript.parentNode) {
                pollScript.parentNode.removeChild(pollScript);
            }
        }, 5000);
    }
}

// Callback function for polling
window.handlePollData = function(data) {
    if (data) {
        console.log('Polling data received successfully');
        safeUpdateDashboard(data);
    } else {
        console.warn('Received empty data from polling');
    }
};

// Initialize dashboard with default values
function initializeDashboard() {
    document.getElementById('total-queries').textContent = '0';
    document.getElementById('qps').textContent = '0.00';
    document.getElementById('uptime').textContent = '0s';
    document.getElementById('avg-response-time').textContent = '0.00 ms';
    document.getElementById('cache-hit-ratio').textContent = '0.00%';
    document.getElementById('cache-hits').textContent = '0';
    document.getElementById('cache-misses').textContent = '0';
}

// Initialize with default values
initializeDashboard();

// Refresh data every 5 seconds as a fallback if WebSocket fails
setInterval(pollMetrics, 5000);

// Ultimate fallback: If nothing works after 20 seconds, create an iframe
setTimeout(function() {
    var loadingIndicator = document.getElementById('loading-indicator');
    if (loadingIndicator && loadingIndicator.style.display !== 'none') {
        console.log('Still no data after 20s, trying iframe approach');

        // Create a message for the user
        loadingIndicator.innerHTML = '<h2>Loading Data...</h2>' +
            '<p>We\'re having trouble loading data directly. Trying alternative method...</p>' +
            '<div id="iframe-container" style="display: none;"></div>';

        // Create an iframe to load the metrics directly
        var iframe = document.createElement('iframe');
        iframe.style.display = 'none';
        iframe.src = '/api/metrics';

        // When the iframe loads, try to extract the data
        iframe.onload = function() {
            try {
                console.log('Iframe loaded, attempting to extract data');

                // Try to get the content
                var iframeContent = iframe.contentDocument || iframe.contentWindow.document;
                var jsonText = iframeContent.body.innerText || iframeContent.body.textContent;

                if (jsonText) {
                    var data = JSON.parse(jsonText);
                    console.log('Successfully extracted data from iframe');
                    safeUpdateDashboard(data);
                }
            } catch (e) {
                console.error('Error extracting data from iframe:', e);

                // Last resort: just hide the loading indicator and show whatever we have
                loadingIndicator.style.display = 'none';
            }
        };

        // Add the iframe to the page
        document.getElementById('iframe-container').appendChild(iframe);

        // Set a timeout to hide the loading indicator regardless
        setTimeout(function() {
            loadingIndicator.style.display = 'none';
        }, 5000);
    }
}, 20000);`
