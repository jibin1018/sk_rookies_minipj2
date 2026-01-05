import { NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';

export async function GET(request: Request, context: { params: Promise<{ scanId: string }> }) {
    try {
        const { scanId } = await context.params;
        const reportDir = path.join(process.cwd(), 'reports');

        // First find the JSON to get the report path, OR guess the report path.
        // Try to guess first to save IO.
        const possibleFiles = [
            `scan_report_${scanId}.md`,
            `infra_scan_report_${scanId}.md`,
            `whitebox_report_${scanId}.md`
        ];

        let content = '';
        let foundPath = '';

        for (const file of possibleFiles) {
            const p = path.join(reportDir, file);
            if (fs.existsSync(p)) {
                foundPath = p;
                break;
            }
        }

        // If not found by name, try checking the JSON
        if (!foundPath) {
            const jsonPath = path.join(reportDir, `scan_result_${scanId}.json`);
            if (fs.existsSync(jsonPath)) {
                const data = JSON.parse(fs.readFileSync(jsonPath, 'utf-8'));
                if (data.report_path && fs.existsSync(data.report_path)) {
                    foundPath = data.report_path;
                }
            }
        }

        if (foundPath) {
            content = fs.readFileSync(foundPath, 'utf-8');
            return NextResponse.json({ content });
        } else {
            return NextResponse.json({ error: 'Report not found' }, { status: 404 });
        }

    } catch (error) {
        return NextResponse.json({ error: 'Internal Error: ' + error }, { status: 500 });
    }
}
