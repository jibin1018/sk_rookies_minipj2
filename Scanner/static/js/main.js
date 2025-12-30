// 유틸리티 함수
const Utils = {
    // 날짜 포맷
    formatDate: (dateStr) => {
        const date = new Date(dateStr);
        return date.toLocaleString('ko-KR');
    },
    
    // 시간 경과 계산
    timeAgo: (dateStr) => {
        const date = new Date(dateStr);
        const now = new Date();
        const seconds = Math.floor((now - date) / 1000);
        
        if (seconds < 60) return `${seconds}초 전`;
        const minutes = Math.floor(seconds / 60);
        if (minutes < 60) return `${minutes}분 전`;
        const hours = Math.floor(minutes / 60);
        if (hours < 24) return `${hours}시간 전`;
        const days = Math.floor(hours / 24);
        return `${days}일 전`;
    },
    
    // 심각도 색상
    getSeverityColor: (severity) => {
        const colors = {
            'CRITICAL': '#f5576c',
            'HIGH': '#ff9800',
            'MEDIUM': '#ffc107',
            'LOW': '#4caf50'
        };
        return colors[severity] || '#999';
    },
    
    // 위험 점수 계산
    calculateRiskScore: (results) => {
        let score = 0;
        results.forEach(r => {
            if (r.status === 'VULNERABLE') {
                const severity = r.severity || 'MEDIUM';
                if (severity === 'CRITICAL') score += 10;
                else if (severity === 'HIGH') score += 5;
                else if (severity === 'MEDIUM') score += 2;
                else score += 1;
            }
        });
        return Math.min(score, 100);
    }
};

// API 클라이언트
class ScannerAPI {
    constructor(baseUrl = '') {
        this.baseUrl = baseUrl;
    }
    
    async startWebScan(targetUrl, useClaude = false, scanTypes = ['all']) {
        const response = await fetch(`${this.baseUrl}/api/scan/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_url: targetUrl,
                use_claude: useClaude,
                scan_types: scanTypes
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || '스캔 시작 실패');
        }
        
        return await response.json();
    }
    
    async startInfraScan(sshHost, sshUser, sshPass, sshPort = 22, categories = ['all']) {
        const response = await fetch(`${this.baseUrl}/api/infra/scan/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ssh_host: sshHost,
                ssh_user: sshUser,
                ssh_pass: sshPass,
                ssh_port: sshPort,
                categories: categories
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || '인프라 스캔 시작 실패');
        }
        
        return await response.json();
    }
    
    async getScanStatus(scanId) {
        const response = await fetch(`${this.baseUrl}/api/scan/status/${scanId}`);
        
        if (!response.ok) {
            throw new Error('스캔 상태 조회 실패');
        }
        
        return await response.json();
    }
    
    async getScanResults(scanId) {
        const response = await fetch(`${this.baseUrl}/api/scan/results/${scanId}`);
        
        if (!response.ok) {
            throw new Error('스캔 결과 조회 실패');
        }
        
        return await response.json();
    }
    
    async getTestsList() {
        const response = await fetch(`${this.baseUrl}/api/tests/list`);
        return await response.json();
    }
    
    async getScanHistory() {
        const response = await fetch(`${this.baseUrl}/api/scans/history`);
        return await response.json();
    }
}

// 스캔 매니저
class ScanManager {
    constructor() {
        this.api = new ScannerAPI();
        this.currentScanId = null;
        this.pollingInterval = null;
    }
    
    async startScan(type, params) {
        try {
            let result;
            
            if (type === 'web') {
                result = await this.api.startWebScan(
                    params.targetUrl,
                    params.useClaude,
                    params.scanTypes
                );
            } else if (type === 'infra') {
                result = await this.api.startInfraScan(
                    params.sshHost,
                    params.sshUser,
                    params.sshPass,
                    params.sshPort,
                    params.categories
                );
            }
            
            this.currentScanId = result.scan_id;
            return result;
            
        } catch (error) {
            console.error('스캔 시작 오류:', error);
            throw error;
        }
    }
    
    startPolling(callback, interval = 2000) {
        if (!this.currentScanId) {
            console.error('스캔 ID가 없습니다');
            return;
        }
        
        this.pollingInterval = setInterval(async () => {
            try {
                const status = await this.api.getScanStatus(this.currentScanId);
                callback(status);
                
                if (status.status === 'completed' || status.status === 'error') {
                    this.stopPolling();
                }
            } catch (error) {
                console.error('폴링 오류:', error);
            }
        }, interval);
    }
    
    stopPolling() {
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
            this.pollingInterval = null;
        }
    }
    
    async getResults() {
        if (!this.currentScanId) {
            throw new Error('스캔 ID가 없습니다');
        }
        
        return await this.api.getScanResults(this.currentScanId);
    }
}

// 알림 시스템
class NotificationSystem {
    static show(message, type = 'info', duration = 3000) {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 25px;
            background: ${type === 'error' ? '#f5576c' : type === 'success' ? '#4facfe' : '#667eea'};
            color: white;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 9999;
            animation: slideIn 0.3s ease;
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }, duration);
    }
}

// 전역 스타일 추가
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// 전역 객체로 export
window.ScannerUtils = Utils;
window.ScannerAPI = ScannerAPI;
window.ScanManager = ScanManager;
window.NotificationSystem = NotificationSystem;