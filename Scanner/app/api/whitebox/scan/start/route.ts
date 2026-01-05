import { NextResponse } from 'next/server';
import { spawn } from 'child_process';
import path from 'path';

export async function POST(request: Request) {
    try {
        const body = await request.json();
        const { repo, commit } = body;

        if (!repo || !commit) {
            return NextResponse.json({ error: 'Repo URL and Commit hash are required' }, { status: 400 });
        }

        const cliPath = path.join(process.cwd(), 'cli.py');
        const pythonCmd = 'python3';

        // Generate Scan ID
        const scanId = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14) + '_whitebox_' + Math.random().toString(36).substr(2, 5);

        const child = spawn(pythonCmd, [
            cliPath,
            'whitebox',
            '--repo', repo,
            '--commit', commit,
            '--scan-id', scanId
        ], {
            detached: true,
            stdio: 'ignore'
        });

        child.unref();

        return NextResponse.json({
            success: true,
            scan_id: scanId,
            message: "Whitebox analysis started"
        });

    } catch (error) {
        console.error(error);
        return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
    }
}
