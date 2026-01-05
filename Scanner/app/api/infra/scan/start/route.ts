import { NextResponse } from 'next/server';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { writeFile } from 'fs/promises';

export async function POST(request: Request) {
    try {
        const contentType = request.headers.get('content-type') || '';

        let args: any = {};
        let pemPath = '';

        if (contentType.includes('multipart/form-data')) {
            const formData = await request.formData();
            args.host = formData.get('ssh_host');
            args.user = formData.get('ssh_user');
            args.port = formData.get('ssh_port') || '22';
            const file = formData.get('pem_file') as File | null;

            if (file) {
                const bytes = await file.arrayBuffer();
                const buffer = Buffer.from(bytes);

                const tempDir = path.join(process.cwd(), 'temp');
                if (!fs.existsSync(tempDir)) {
                    fs.mkdirSync(tempDir);
                }
                pemPath = path.join(tempDir, `key_${Date.now()}.pem`);
                await writeFile(pemPath, buffer);
                fs.chmodSync(pemPath, 0o600);

                args.pem = pemPath;
            }
        } else {
            const body = await request.json();
            args.host = body.ssh_host;
            args.user = body.ssh_user;
            args.port = body.ssh_port || '22';
            args.password = body.ssh_pass;
        }

        if (!args.host || !args.user) {
            return NextResponse.json({ error: 'Required fields missing' }, { status: 400 });
        }

        const cliPath = path.join(process.cwd(), 'cli.py');
        const pythonCmd = 'python3';

        const scanId = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14) + '_' + Math.random().toString(36).substr(2, 5);

        const cliArgs = [
            cliPath,
            'infra',
            '--host', args.host,
            '--user', args.user,
            '--port', args.port,
            '--scan-id', scanId
        ];

        if (args.password) {
            cliArgs.push('--password', args.password);
        }
        if (args.pem) {
            cliArgs.push('--pem', args.pem);
        }

        const child = spawn(pythonCmd, cliArgs, {
            detached: true,
            stdio: 'ignore'
        });

        child.unref();

        // PEM cleanup is tricky with detached process. 
        // Ideally cli.py should delete it, or we rely on OS cleanup / manual cron.
        // For now, we leave it in temp.

        return NextResponse.json({
            success: true,
            scan_id: scanId,
            message: "Scan started in background"
        });

    } catch (error) {
        console.error(error);
        return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
    }
}
