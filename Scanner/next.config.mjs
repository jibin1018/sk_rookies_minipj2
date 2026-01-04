/** @type {import('next').NextConfig} */
const nextConfig = {
    reactStrictMode: true,
    async rewrites() {
        return [
            {
                source: '/api/:path*',
                destination: 'http://127.0.0.1:5003/api/:path*',
            },
            {
                source: '/download/:path*',
                destination: 'http://127.0.0.1:5003/download/:path*',
            },
            {
                source: '/report/:path*',
                destination: 'http://127.0.0.1:5003/report/:path*',
            }
        ]
    },
};

export default nextConfig;
