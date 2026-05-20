/**
 * Cyber Threat Prediction System - Frontend JavaScript
 * Handles form validation, API calls, and UI updates
 */

// Global variables
let csvResults = null;          // Stores CSV processing results
let realtimeInterval = null;    // Interval for real-time simulation
let trafficChart = null;        // Chart.js instance for traffic
let attackChart = null;         // Chart.js instance for attack types

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeApplication();
});

/**
 * Initialize the application
 * Sets up event listeners and enhances form fields
 */
function initializeApplication() {
    showInputOptions();  // Show the appropriate input method
    setupEventListeners();
    enhanceManualInputFields();
}

// ========================
// INPUT METHOD SELECTION
// ========================

/**
 * Show the appropriate input method based on selection
 */
function showInputOptions() {
    const method = document.getElementById('inputMethod').value;
    
    // Hide all sections first
    document.getElementById('textboxInputs').style.display = 'none';
    document.getElementById('importInput').style.display = 'none';
    document.getElementById('realTimeInput').style.display = 'none';
    
    // Show selected section
    if (method === 'textboxes') {
        document.getElementById('textboxInputs').style.display = 'block';
    } else if (method === 'import') {
        document.getElementById('importInput').style.display = 'block';
    } else if (method === 'real-time') {
        document.getElementById('realTimeInput').style.display = 'block';
    }
}

/**
 * Set up all event listeners
 */
function setupEventListeners() {
    // Input method selector
    document.getElementById('inputMethod').addEventListener('change', showInputOptions);
    
    // Manual form handling
    const manualForm = document.querySelector('#manualPredictionForm');
    if (manualForm) {
        manualForm.addEventListener('submit', handleManualSubmit);
    }
    
    // CSV handling
    document.getElementById('previewBtn')?.addEventListener('click', handleCsvPreview);
    document.getElementById('processBtn')?.addEventListener('click', handleCsvProcess);
    document.getElementById('exportFullBtn')?.addEventListener('click', exportFullResults);
    document.getElementById('exportAttacksBtn')?.addEventListener('click', exportAttackResults);
    
    // Real-time handling
    document.getElementById('startRealtimeBtn')?.addEventListener('click', startRealtimeMonitoring);
    document.getElementById('stopRealtimeBtn')?.addEventListener('click', stopRealtimeMonitoring);
}

/**
 * Enhance manual input fields with better UI controls
 */
function enhanceManualInputFields() {
    // Protocol dropdown - replace text input with select
    const protocolInput = document.getElementById('protocol');
    if (protocolInput && protocolInput.tagName === 'INPUT') {
        const parent = protocolInput.parentElement;
        parent.innerHTML = `
            <label for="protocol">Protocol</label>
            <select id="protocol" name="protocol" class="form-control" required>
                <option value="ICMP">ICMP (0)</option>
                <option value="UDP">UDP (1)</option>
                <option value="TCP" selected>TCP (2)</option>
            </select>
        `;
    }

    // Flags dropdown - replace text input with select
    const flagsInput = document.getElementById('flags');
    if (flagsInput && flagsInput.tagName === 'INPUT') {
        const parent = flagsInput.parentElement;
        parent.innerHTML = `
            <label for="flags">Flags</label>
            <select id="flags" name="flags" class="form-control" required>
                <option value="SYN" selected>SYN (0)</option>
                <option value="ACK">ACK (1)</option>
                <option value="FIN">FIN (2)</option>
                <option value="PSH">PSH (3)</option>
            </select>
        `;
    }

    // IP validation
    document.getElementById('source_ip')?.addEventListener('blur', validateIPField);
    document.getElementById('destination_ip')?.addEventListener('blur', validateIPField);

    // Port validation
    document.getElementById('source_port')?.addEventListener('blur', validatePortField);
    document.getElementById('destination_port')?.addEventListener('blur', validatePortField);

    // Numeric validation for all numeric fields
    const numericFields = [
        'packet_length', 'duration', 'bytes_sent', 'bytes_received',
        'flow_packets_per_second', 'flow_bytes_per_second', 'avg_packet_size',
        'total_fwd_packets', 'total_bwd_packets', 'fwd_header_length',
        'bwd_header_length', 'sub_flow_fwd_bytes', 'sub_flow_bwd_bytes'
    ];
    
    numericFields.forEach(field => {
        const el = document.getElementById(field);
        if (el) {
            el.addEventListener('blur', validateNumericField);
            el.addEventListener('input', validateNumericField);
        }
    });
}

// ========================
// VALIDATION FUNCTIONS
// ========================

/**
 * Validate IP address field
 */
function validateIPField(e) {
    const input = e.target;
    const value = input.value.trim();
    const group = input.closest('.input-group');
    
    // Reset validation classes
    group.classList.remove('is-invalid');
    group.classList.remove('is-valid');
    
    // Check for required field
    if (!value) {
        if (input.required) {
            group.classList.add('is-invalid');
            return false;
        }
        return true;
    }
    
    // Validate IP format
    if (!/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(value)) {
        group.classList.add('is-invalid');
        return false;
    }
    
    // If valid
    group.classList.add('is-valid');
    return true;
}

/**
 * Validate port field (0-65535)
 */
function validatePortField(e) {
    const input = e.target;
    const value = input.value.trim();
    const group = input.closest('.input-group');
    
    group.classList.remove('is-invalid');
    group.classList.remove('is-valid');
    
    if (!value) {
        if (input.required) {
            group.classList.add('is-invalid');
            return false;
        }
        return true;
    }
    
    // Check if valid integer (no decimals) and within port range
    if (!/^\d+$/.test(value) || value.includes('.') || value.includes(',')) {
        group.classList.add('is-invalid');
        return false;
    }
    
    const port = parseInt(value);
    if (isNaN(port) || port < 0 || port > 65535) {
        group.classList.add('is-invalid');
        return false;
    }
    
    group.classList.add('is-valid');
    return true;
}

/**
 * Validate numeric field
 */
function validateNumericField(e) {
    const input = e.target;
    const value = input.value.trim();
    const group = input.closest('.input-group');
    
    group.classList.remove('is-invalid');
    group.classList.remove('is-valid');
    
    if (!value) {
        if (input.required) {
            group.classList.add('is-invalid');
            return false;
        }
        return true;
    }
    
    // Check if valid number (integer or float)
    if (!/^[0-9]*\.?[0-9]+$/.test(value)) {
        group.classList.add('is-invalid');
        return false;
    }
    
    group.classList.add('is-valid');
    return true;
}

/**
 * Validate the entire manual form
 */
function validateManualForm() {
    let isValid = true;
    
    // Validate IPs
    if (!validateIPField({target: document.getElementById('source_ip')})) isValid = false;
    if (!validateIPField({target: document.getElementById('destination_ip')})) isValid = false;
    
    // Validate ports
    if (!validatePortField({target: document.getElementById('source_port')})) isValid = false;
    if (!validatePortField({target: document.getElementById('destination_port')})) isValid = false;
    
    // Validate all numeric fields
    const numericFields = [
        'packet_length', 'duration', 'bytes_sent', 'bytes_received',
        'flow_packets_per_second', 'flow_bytes_per_second', 'avg_packet_size',
        'total_fwd_packets', 'total_bwd_packets', 'fwd_header_length',
        'bwd_header_length', 'sub_flow_fwd_bytes', 'sub_flow_bwd_bytes'
    ];
    
    numericFields.forEach(field => {
        const input = document.getElementById(field);
        if (input && !validateNumericField({target: input})) isValid = false;
    });
    
    return isValid;
}

// ========================
// MANUAL INPUT HANDLING
// ========================

/**
 * Handle manual form submission
 */
function handleManualSubmit(e) {
    e.preventDefault();
    
    // Validate form before submission
    if (!validateManualForm()) {
        Swal.fire({
            title: 'Validation Error',
            text: 'Please correct the highlighted fields before submitting',
            icon: 'error'
        });
        
        // Scroll to first error
        document.querySelector('.is-invalid')?.scrollIntoView({
            behavior: 'smooth',
            block: 'center'
        });
        return;
    }
    
    const form = e.target;
    const submitBtn = form.querySelector('button[type="submit"]');
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());
    
    // Convert numeric fields to numbers
    const numericFields = [
        'packet_length', 'duration', 'source_port', 'destination_port',
        'bytes_sent', 'bytes_received', 'flow_packets_per_second',
        'flow_bytes_per_second', 'avg_packet_size', 'total_fwd_packets',
        'total_bwd_packets', 'fwd_header_length', 'bwd_header_length',
        'sub_flow_fwd_bytes', 'sub_flow_bwd_bytes'
    ];
    
    numericFields.forEach(field => {
        if (data[field]) {
            data[field] = parseFloat(data[field]);
        }
    });
    
    // Show loading state
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
    
    // Send prediction request to server
    fetch('/predict_manual', {
        method: 'POST',
        headers: { 
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => {
                throw new Error(err.error || 'Request failed');
            });
        }
        return response.json();
    })
    .then(result => {
        if (result.error) throw new Error(result.error);
        
        // Update UI with prediction results
        const predictionDiv = document.querySelector('.prediction-result');
        const recommendationDiv = document.querySelector('.recommendation-box');
        
        predictionDiv.textContent = result.prediction;
        predictionDiv.className = `prediction-result ${result.prediction === 'Normal' ? 'normal' : 'malicious'}`;
        predictionDiv.style.display = 'block';
        
        recommendationDiv.innerHTML = `
            <div class="recommendation-title">Security Recommendations:</div>
            ${result.recommendation.replace(/\n/g, '<br>')}
        `;
        recommendationDiv.style.display = 'block';
        
        // Scroll to results
        predictionDiv.scrollIntoView({ behavior: 'smooth', block: 'center' });
    })
    .catch(error => {
        console.error('Prediction error:', error);
        Swal.fire({
            title: 'Error',
            text: error.message || 'Prediction failed',
            icon: 'error'
        });
    })
    .finally(() => {
        submitBtn.disabled = false;
        submitBtn.textContent = 'PREDICT';
    });
}

// ========================
// CSV INPUT HANDLING
// ========================

/**
 * Handle CSV preview request
 */
function handleCsvPreview(e) {
    e.preventDefault();
    const fileInput = document.getElementById('csv_file');
    
    if (!fileInput.files.length) {
        Swal.fire('Error', 'Please select a CSV file first', 'error');
        return;
    }
    
    const formData = new FormData();
    formData.append('csv_file', fileInput.files[0]);
    
    const btn = e.target;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
    
    fetch('/preview_csv', {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (!response.ok) {
            return response.text().then(text => {
                throw new Error(text || 'Request failed');
            });
        }
        return response.json();
    })
    .then(data => {
        if (data.error) throw new Error(data.error);
        displayCsvPreview(data);
    })
    .catch(error => {
        Swal.fire('Error', error.message || 'Failed to preview CSV', 'error');
    })
    .finally(() => {
        btn.disabled = false;
        btn.textContent = 'Preview CSV';
    });
}

/**
 * Display CSV preview data
 */
function displayCsvPreview(data) {
    const previewSection = document.getElementById('previewSection');
    const previewHeader = document.getElementById('previewHeader');
    const previewBody = document.getElementById('previewBody');
    const mappingBody = document.getElementById('mappingBody');
    
    // Clear previous content
    previewHeader.innerHTML = '';
    previewBody.innerHTML = '';
    mappingBody.innerHTML = '';
    
    // Set up headers
    data.columns.forEach(col => {
        const th = document.createElement('th');
        th.textContent = col;
        previewHeader.appendChild(th);
    });
    
    // Add preview rows
    data.preview.forEach(row => {
        const tr = document.createElement('tr');
        data.columns.forEach(col => {
            const td = document.createElement('td');
            td.textContent = row[col] !== undefined ? row[col] : '';
            tr.appendChild(td);
        });
        previewBody.appendChild(tr);
    });
    
    // Set up column mapping interface
    data.columns.forEach(col => {
        const tr = document.createElement('tr');
        
        // CSV Column
        const tdCol = document.createElement('td');
        tdCol.textContent = col;
        tr.appendChild(tdCol);
        
        // Mapping dropdown
        const tdMap = document.createElement('td');
        const select = document.createElement('select');
        select.className = 'form-select';
        
        // Add empty option
        const emptyOption = document.createElement('option');
        emptyOption.value = '';
        emptyOption.textContent = '-- Ignore --';
        select.appendChild(emptyOption);
        
        // Add model columns as options
        data.model_columns.forEach(modelCol => {
            const option = document.createElement('option');
            option.value = modelCol;
            option.textContent = modelCol;
            
            // Try to auto-match based on column name
            if (col.toLowerCase().includes(modelCol.split('_')[0].toLowerCase())) {
                option.selected = true;
            }
            
            select.appendChild(option);
        });
        
        tdMap.appendChild(select);
        tr.appendChild(tdMap);
        mappingBody.appendChild(tr);
    });
    
    previewSection.style.display = 'block';
}

/**
 * Process CSV file and get predictions
 */
function handleCsvProcess(e) {
    e.preventDefault();
    
    // Get column mapping from form
    const mapping = {};
    document.querySelectorAll('#mappingBody tr').forEach(row => {
        const csvCol = row.cells[0].textContent;
        const modelCol = row.cells[1].querySelector('select').value;
        if (modelCol) mapping[csvCol] = modelCol;
    });
    
    if (Object.keys(mapping).length === 0) {
        Swal.fire('Error', 'Please map at least one column', 'error');
        return;
    }
    
    const fileInput = document.getElementById('csv_file');
    const formData = new FormData();
    formData.append('csv_file', fileInput.files[0]);
    formData.append('column_mapping', JSON.stringify(mapping));
    
    const btn = e.target;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
    
    fetch('/process_csv', {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (!response.ok) {
            return response.text().then(text => {
                throw new Error(text || 'Request failed');
            });
        }
        return response.json();
    })
    .then(data => {
        if (data.error) throw new Error(data.error);
        displayCsvResults(data);
    })
    .catch(error => {
        Swal.fire('Error', error.message || 'Failed to process CSV', 'error');
    })
    .finally(() => {
        btn.disabled = false;
        btn.textContent = 'Process and Predict';
    });
}

/**
 * Display CSV processing results
 */
function displayCsvResults(data) {
    const resultsSection = document.getElementById('resultsSection');
    const resultsBody = document.getElementById('resultsBody');
    
    // Update stats
    document.getElementById('totalRecords').textContent = data.stats.total_records;
    document.getElementById('normalCount').textContent = data.stats.normal_count;
    document.getElementById('attackCount').textContent = data.stats.attack_count;
    
    // Update attack types
    const attackTypesList = document.getElementById('attackTypes');
    attackTypesList.innerHTML = '';
    
    if (data.stats.attack_types) {
        for (const [type, count] of Object.entries(data.stats.attack_types)) {
            const li = document.createElement('li');
            li.textContent = `${type}: ${count} occurrences`;
            attackTypesList.appendChild(li);
        }
    } else {
        const li = document.createElement('li');
        li.textContent = 'No attack traffic detected';
        attackTypesList.appendChild(li);
    }
    
    // Display sample results
   resultsBody.innerHTML = '';
    data.sample_results.forEach(row => {
        const tr = document.createElement('tr');
        tr.className = row.prediction === 'Normal' ? 'normal' : 'malicious';
        
        // Only show prediction and recommendation
        const cells = [
            row.prediction,
            row.recommendation
        ];
        
        cells.forEach(cell => {
            const td = document.createElement('td');
            if (typeof cell === 'string' && cell.includes('\n')) {
                const content = document.createElement('div');
                content.className = 'recommendation-cell';
                content.innerHTML = cell.replace(/\n/g, '<br>');
                td.appendChild(content);
            } else {
                td.textContent = cell;
            }
            tr.appendChild(td);
        });
        
        resultsBody.appendChild(tr);
    });
    
    // Store results for export
    window.csvResults = data.all_results;
    resultsSection.style.display = 'block';
}

// ========================
// EXPORT FUNCTIONALITY
// ========================

/**
 * Export all results as CSV
 */
function exportFullResults() {
    if (!window.csvResults) {
        Swal.fire('Error', 'No results to export', 'error');
        return;
    }
    exportResults(window.csvResults);
}

/**
 * Export only attack results as CSV
 */
function exportAttackResults() {
    if (!window.csvResults) {
        Swal.fire('Error', 'No results to export', 'error');
        return;
    }
    
    const attackResults = window.csvResults.filter(row => row.prediction !== 'Normal');
    if (attackResults.length === 0) {
        Swal.fire('Info', 'No attack records to export', 'info');
        return;
    }
    
    exportResults(attackResults);
}

/**
 * Generic export function
 */
function exportResults(results) {
    fetch('/export_results', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ results })
    })
    .then(response => {
        if (!response.ok) {
            return response.text().then(text => {
                throw new Error(text || 'Export failed');
            });
        }
        return response.blob();
    })
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'cyber_threat_predictions.csv';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();
    })
    .catch(error => {
        Swal.fire('Error', error.message || 'Failed to export results', 'error');
    });
}

// ========================
// REAL-TIME MONITORING
// ========================

/**
 * Start real-time monitoring simulation
 */
function startRealtimeMonitoring() {
    const startBtn = document.getElementById('startRealtimeBtn');
    const stopBtn = document.getElementById('stopRealtimeBtn');

    startBtn.disabled = true;
    stopBtn.disabled = false;

    initRealtimeCharts();

    // Initialize counters
    let packetCount = 0;
    let normalCount = 0;
    let attackCount = 0;
    const attackTypes = {
        'DDoS': 0,
        'Ransomware': 0,
        'Brute Force': 0
    };

    // Start simulation interval
    realtimeInterval = setInterval(() => {
        packetCount++;
        document.getElementById('packetsCount').textContent = packetCount;

        // Randomly determine if this is an attack (20% chance)
        const isAttack = Math.random() < 0.2;

        // Generate random network data
        const randomData = {
            source_ip: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            destination_ip: `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            protocol: ['tcp', 'udp', 'icmp'][Math.floor(Math.random() * 3)],
            packet_length: Math.floor(Math.random() * 1500) + 100,
            duration: (Math.random() * 10).toFixed(2),
            source_port: Math.floor(Math.random() * 65535),
            destination_port: Math.floor(Math.random() * 65535),
            bytes_sent: Math.floor(Math.random() * 10000),
            bytes_received: Math.floor(Math.random() * 10000),
            flags: ['syn', 'ack', 'fin', 'psh'][Math.floor(Math.random() * 4)],
            flow_packets_per_second: (Math.random() * 1000).toFixed(2),
            flow_bytes_per_second: (Math.random() * 1000000).toFixed(2),
            avg_packet_size: (Math.random() * 500).toFixed(2),
            total_fwd_packets: Math.floor(Math.random() * 100),
            total_bwd_packets: Math.floor(Math.random() * 50),
            fwd_header_length: Math.floor(Math.random() * 40),
            bwd_header_length: Math.floor(Math.random() * 40),
            sub_flow_fwd_bytes: Math.floor(Math.random() * 1000),
            sub_flow_bwd_bytes: Math.floor(Math.random() * 500)
        };

        // Send to server for prediction
        fetch('/predict_realtime', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(randomData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.prediction && data.prediction !== 'Normal') {
                addRealtimeAlert(data.prediction);
                attackCount++;  // Increment attack count if an attack is predicted
                document.getElementById('realtimeAttackCount').textContent = attackCount;
                attackTypes[data.prediction]++; // Update attack type count
            } else {
                normalCount++; // Increment normal count if normal traffic is predicted
                document.getElementById('realtimeNormalCount').textContent = normalCount;
            }

            // Update charts
            updateRealtimeCharts(normalCount, attackCount, attackTypes);
        });
    }, 3000); // Update every 3 seconds
}

/**
 * Stop real-time monitoring
 */
function stopRealtimeMonitoring() {
    clearInterval(realtimeInterval);
    realtimeInterval = null;
    
    document.getElementById('startRealtimeBtn').disabled = false;
    document.getElementById('stopRealtimeBtn').disabled = true;
}

/**
 * Add alert to real-time monitoring display
 */
function addRealtimeAlert(attackType) {
    const alertsContainer = document.getElementById('alertsContainer');
    // Remove placeholder if exists
    const placeholder = alertsContainer.querySelector('.alert-placeholder');
    if (placeholder) alertsContainer.removeChild(placeholder);
    
    // Create new alert
    const alertDiv = document.createElement('div');
    alertDiv.className = `realtime-alert ${attackType.toLowerCase().replace(' ', '-')}`;
    alertDiv.innerHTML = `
        <div class="alert-header">
            <span class="alert-type">${attackType}</span>
            <span class="alert-time">${new Date().toLocaleTimeString()}</span>
        </div>
        <div class="alert-message">Potential ${attackType} attack detected</div>
    `;
    alertsContainer.insertBefore(alertDiv, alertsContainer.firstChild);
}

/**
 * Initialize real-time monitoring charts
 */
function initRealtimeCharts() {
    const trafficCtx = document.getElementById('trafficChart').getContext('2d');
    trafficChart = new Chart(trafficCtx, {
        type: 'doughnut',
        data: {
            labels: ['Normal', 'Attack'],
            datasets: [{
                data: [0, 0],
                backgroundColor: ['#28a745', '#dc3545']
            }]
        }
    });
    
    const attackCtx = document.getElementById('attackChart').getContext('2d');
    attackChart = new Chart(attackCtx, {
        type: 'bar',
        data: {
            labels: ['DDoS', 'Ransomware', 'Brute Force'],
            datasets: [{
                label: 'Attack Types',
                data: [0, 0, 0],
                backgroundColor: ['#ffc107', '#fd7e14', '#6f42c1']
            }]
        }
    });
}

/**
 * Update real-time monitoring charts
 */
function updateRealtimeCharts(normal, attack, attackTypes) {
    trafficChart.data.datasets[0].data = [normal, attack];
    trafficChart.update();
    
    attackChart.data.datasets[0].data = [
        attackTypes['DDoS'],
        attackTypes['Ransomware'],
        attackTypes['Brute Force']
    ];
    attackChart.update();
}