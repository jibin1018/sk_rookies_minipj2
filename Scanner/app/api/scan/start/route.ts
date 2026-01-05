import { NextResponse } from 'next/server';
import { spawn } from 'child_process';
import path from 'path';

export async function POST(request: Request) {
    try {
        const body = await request.json();
        const { target_url, use_infra_detection } = body;

        if (!target_url) {
            return NextResponse.json({ error: 'Target URL is required' }, { status: 400 });
        }

        // CLI 스크립트 경로
        const cliPath = path.join(process.cwd(), 'cli.py');
        const pythonCmd = 'python3';

        // Generate Scan ID
        const scanId = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14) + '_' + Math.random().toString(36).substr(2, 5);

        // Spawn process detached
        const child = spawn(pythonCmd, [
            cliPath,
            'web',
            '--url', target_url,
            '--scan-id', scanId,
            ...(use_infra_detection ? ['--infra'] : [])
        ], {
            detached: true,
            stdio: 'ignore'
        });

        child.unref();

        return NextResponse.json({
            success: true,
            scan_id: scanId,
            message: "Scan started in background"
        });

    } catch (error) {
        return NextResponse.json({ error: 'Internal Server Error: ' + error }, { status: 500 });
    }
}
