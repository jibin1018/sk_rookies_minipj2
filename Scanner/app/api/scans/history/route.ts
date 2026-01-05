import { NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';

export async function GET() {
    try {
        const reportDir = path.join(process.cwd(), 'reports');
        if (!fs.existsSync(reportDir)) {
            return NextResponse.json({ scans: [] });
        }

        const files = fs.readdirSync(reportDir).filter(f => f.startsWith('scan_result_') && f.endsWith('.json'));

        // Sort by modification time desc (newest first)
        files.sort((a, b) => {
            return fs.statSync(path.join(reportDir, b)).mtime.getTime() -
                fs.statSync(path.join(reportDir, a)).mtime.getTime();
        });

        const scans = [];
        for (const file of files) {
            try {
                const content = fs.readFileSync(path.join(reportDir, file), 'utf-8');
                const data = JSON.parse(content);

                // Format for UI
                let vulnerable = 0;
                if (data.results) {
                    if (Array.isArray(data.results)) {
                        vulnerable = data.results.filter((r: any) => r.status === 'VULNERABLE').length;
                    }
                }
                if (data.summary && data.summary.vulnerable) {
                    vulnerable = data.summary.vulnerable;
                }

                scans.push({
                    scan_id: data.scan_id,
                    type: data.type || 'web',
                    status: data.status,
                    target: data.target_url || data.target || 'Unknown',
                    started_at: data.started_at,
                    summary: {
                        total: data.results ? data.results.length : 0,
                        vulnerable: vulnerable
                    }
                });
            } catch (e) {
                console.error('Error parsing scan file:', file, e);
            }
        }

        return NextResponse.json({ scans });

    } catch (error) {
        return NextResponse.json({ error: 'Internal Error' }, { status: 500 });
    }
}
