import { NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';

export async function GET(request: Request, context: { params: Promise<{ scanId: string }> }) {
    try {
        const { scanId } = await context.params;

        if (!scanId) {
            return NextResponse.json({ error: 'Scan ID required' }, { status: 400 });
        }

        const reportDir = path.join(process.cwd(), 'reports');
        const filePath = path.join(reportDir, `scan_result_${scanId}.json`);

        if (!fs.existsSync(filePath)) {
            // If file doesn't exist yet, it might be starting up.
            // But if user just got scanId from start API, file SHOULD exist basically immediately
            // because cli.py creates it at start.
            // If not found, return pending or running placeholder?
            // Or 404 if it's invalid.
            return NextResponse.json({
                scan_id: scanId,
                status: 'running',
                progress: 0,
                message: "Initializing..."
            });
        }

        const fileContent = fs.readFileSync(filePath, 'utf-8');
        const data = JSON.parse(fileContent);

        return NextResponse.json(data);

    } catch (error) {
        return NextResponse.json({ error: 'Failed to read status: ' + error }, { status: 500 });
    }
}
