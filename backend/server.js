const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// GET /health route for backend engine status
app.get('/health', (req, res) => {
    res.json({ status: 'ok', engine: 'Slither', online: true });
});

// POST /audit route
app.post('/audit', async (req, res) => {
    const { code } = req.body || {};

    // Validation
    if (!code || typeof code !== 'string' || !code.trim()) {
        return res.status(400).json({ error: 'Contract code required' });
    }

    if (code.split('\n').length > 10000) {
        return res.status(400).json({ error: 'Contract too large' });
    }

    // Unique temp file
    const tempFile = path.join(__dirname, `contract_${Date.now()}.sol`);

    try {
        // Save contract to temp file
        fs.writeFileSync(tempFile, code);

        // Run Slither
        const results = await runSlither(tempFile);

        // Send results
        res.json(results);

    } catch (error) {
        res.status(500).json({ error: error.message });

    } finally {
        // Always delete temp file
        if (fs.existsSync(tempFile)) {
            fs.unlinkSync(tempFile);
        }
    }
});

// Run Slither
function runSlither(filePath) {
    const outputFile = path.join(__dirname, `slither_output_${Date.now()}.json`);
    return new Promise((resolve, reject) => {
        exec(`slither "${filePath}" --json "${outputFile}"`, (err, stdout, stderr) => {
            try {
                if (fs.existsSync(outputFile)) {
                    const raw = fs.readFileSync(outputFile, 'utf8');
                    try {
                        fs.unlinkSync(outputFile);
                    } catch {}
                    const data = JSON.parse(raw);
                    const parsed = parseSlither(data);
                    resolve(parsed);
                } else {
                    resolve([]);
                }
            } catch (e) {
                if (fs.existsSync(outputFile)) {
                    try {
                        fs.unlinkSync(outputFile);
                    } catch {}
                }
                resolve([]); // Slither crash → empty results
            }
        });
    });
}

// Parse Slither JSON → clean format
function parseSlither(data) {
    if (!data.results || !data.results.detectors) return [];

    return data.results.detectors.map(d => ({
        tool: 'Slither',
        name: d.check,
        severity: mapSeverity(d.impact),
        description: d.description,
        line: d.elements?.[0]?.source_mapping?.lines?.[0] || 'N/A'
    }));
}

// Map Slither severity to our format
function mapSeverity(impact) {
    const map = {
        'High': 'high',
        'Medium': 'medium',
        'Low': 'low',
        'Informational': 'info',
        'Optimization': 'info'
    };
    return map[impact] || 'info';
}

app.listen(3000, () => {
    console.log('Server running at http://localhost:3000');
});