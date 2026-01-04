"use client"

import { Suspense, useState, useEffect, useRef } from "react"
import { Shield, Search, Server, Database, Globe, Layers, CheckCircle2, Award, FileCheck, Wifi, WifiOff, AlertTriangle, Loader2, ArrowLeft, History, FileText, Check, XCircle, BookOpen, Lock } from "lucide-react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"
import rehypeRaw from "rehype-raw"

// --- Types ---
interface ScanResult {
  scan_id: string
  type: 'web' | 'infrastructure'
  status: 'running' | 'completed' | 'error'
  progress: number
  target: string
  started_at: string
  completed_at?: string
  results?: any[]
  summary?: {
    total: number
    vulnerable: number
  }
  current_test?: string
  error?: string
  report_path?: string
}

interface HistoryItem {
  scan_id: string
  type: 'web' | 'infrastructure'
  status: string
  target: string
  started_at: string
  summary: {
    total: number | string
    vulnerable: number | string
  }
}

// --- Components ---

function FeatureCards() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
      <Card className="bg-blue-50/50 border-blue-100 shadow-sm">
        <CardContent className="flex items-center gap-4 p-6">
          <div className="p-3 bg-blue-100 text-blue-600 rounded-full">
            <CheckCircle2 className="w-6 h-6" />
          </div>
          <div>
            <h3 className="font-bold text-slate-900">OWASP Top 10</h3>
            <p className="text-sm text-slate-500">완전 준수</p>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-emerald-50/50 border-emerald-100 shadow-sm">
        <CardContent className="flex items-center gap-4 p-6">
          <div className="p-3 bg-emerald-100 text-emerald-600 rounded-full">
            <Award className="w-6 h-6" />
          </div>
          <div>
            <h3 className="font-bold text-slate-900">KISA 가이드</h3>
            <p className="text-sm text-slate-500">보안 기준 준수</p>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-orange-50/50 border-orange-100 shadow-sm">
        <CardContent className="flex items-center gap-4 p-6">
          <div className="p-3 bg-orange-100 text-orange-600 rounded-full">
            <FileCheck className="w-6 h-6" />
          </div>
          <div>
            <h3 className="font-bold text-slate-900">CIS 벤치마크</h3>
            <p className="text-sm text-slate-500">국제 표준</p>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-purple-50/50 border-purple-100 shadow-sm">
        <CardContent className="flex items-center gap-4 p-6">
          <div className="p-3 bg-purple-100 text-purple-600 rounded-full">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h3 className="font-bold text-slate-900">CVE 데이터베이스</h3>
            <p className="text-sm text-slate-500">실시간 연동</p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

function ScanInfoSidebar() {
  return (
    <Card className="border-slate-200 shadow-sm h-full">
      <CardHeader>
        <CardTitle className="text-lg">스캔 범위</CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div>
          <h4 className="font-semibold text-slate-800 flex items-center gap-2 mb-2">
            <CheckCircle2 className="w-4 h-4 text-blue-500" />
            OWASP Top 10 (2021)
          </h4>
          <ul className="text-sm text-slate-500 space-y-1 pl-6 list-disc">
            <li>A01: 접근 제어 실패 (Broken Access Control)</li>
            <li>A02: 암호화 오류 (Cryptographic Failures)</li>
            <li>A03: 인젝션 (Injection)</li>
            <li>A04: 안전하지 않은 설계 (Insecure Design)</li>
            <li>A05: 보안 설정 오류 (Security Misconfiguration)</li>
            <li>A06-A10: 취약한 컴포넌트, 인증, 무결성 등</li>
          </ul>
        </div>

        <div>
          <h4 className="font-semibold text-slate-800 flex items-center gap-2 mb-2">
            <Award className="w-4 h-4 text-emerald-500" />
            KISA 보안 가이드
          </h4>
          <ul className="text-sm text-slate-500 space-y-1 pl-6 list-disc">
            <li>소프트웨어 개발 보안 가이드 준수</li>
            <li>주요정보통신기반시설 취약점 점검</li>
            <li>암호화 알고리즘 보안성 검증</li>
          </ul>
        </div>

        <div>
          <h4 className="font-semibold text-slate-800 flex items-center gap-2 mb-2">
            <Shield className="w-4 h-4 text-orange-500" />
            추가 보안 검사
          </h4>
          <ul className="text-sm text-slate-500 space-y-1 pl-6 list-disc">
            <li>XSS, CSRF, SQLi 등 웹 취약점 정밀 진단</li>
            <li>보안 헤더 (CSP, HSTS) 설정 확인</li>
            <li>L7 레벨 취약점 및 프레임워크 탐지</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  )
}

function ProgressView({ scanId, onBack }: { scanId: string, onBack: () => void }) {
  const [status, setStatus] = useState<ScanResult | null>(null)
  const [reportContent, setReportContent] = useState<string | null>(null)
  const [loadingReport, setLoadingReport] = useState(false)
  const pollingRef = useRef<NodeJS.Timeout | null>(null)

  const handleViewReport = async () => {
    setLoadingReport(true)
    try {
      const res = await fetch(`/api/report/raw/${scanId}`)
      if (res.ok) {
        const data = await res.json()
        setReportContent(data.content || "")
      }
    } catch (e) {
      console.error("Failed to fetch report", e)
    } finally {
      setLoadingReport(false)
    }
  }

  useEffect(() => {
    const poll = async () => {
      try {
        const res = await fetch(`/api/scan/status/${scanId}`)
        if (res.ok) {
          const data = await res.json()
          setStatus(data)
          if (data.status === 'completed' || data.status === 'error') {
            if (pollingRef.current) clearInterval(pollingRef.current)
          }
        }
      } catch (e) {
        console.error("Polling error", e)
      }
    }

    poll() // initial call
    pollingRef.current = setInterval(poll, 2000)

    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current)
    }
  }, [scanId])

  if (!status) return (
    <div className="flex flex-col items-center justify-center p-20 gap-4 bg-white rounded-xl border border-slate-200">
      <Loader2 className="animate-spin w-12 h-12 text-blue-600" />
      <p className="text-lg text-slate-500">진단 상태를 불러오는 중...</p>
    </div>
  )

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-5 duration-500">
      <Card className="border-slate-200 shadow-md">
        <CardHeader className="bg-slate-50/50 border-b border-slate-100">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-xl flex items-center gap-2">
                {status.status === 'running' && <Loader2 className="animate-spin text-blue-500" />}
                {status.status === 'completed' && <CheckCircle2 className="text-green-500" />}
                {status.status === 'error' && <XCircle className="text-red-500" />}
                {status.status === 'running' ? '보안 진단 진행 중' : (status.status === 'completed' ? '진단 완료' : '진단 실패')}
              </CardTitle>
              <CardDescription className="mt-1">
                대상: {status.target} | 유형: {status.type === 'web' ? '웹' : '인프라'}
              </CardDescription>
            </div>
            <Badge variant="outline" className="text-sm px-3 py-1 bg-white">ID: {scanId}</Badge>
          </div>
        </CardHeader>

        <CardContent className="p-6 space-y-6">
          <div className="space-y-2">
            <div className="flex justify-between text-sm font-medium text-slate-700">
              <span>진행률</span>
              <span>{Math.round(status.progress)}%</span>
            </div>
            <Progress value={status.progress} className="h-3 w-full bg-slate-100" />
          </div>

          <div className="bg-slate-900 text-slate-200 p-6 rounded-lg font-mono text-sm min-h-[240px] max-h-[400px] overflow-y-auto shadow-inner">
            <div className="flex flex-col gap-2">
              <p className="text-green-400 opacity-80">$ initiating {status.type} scan sequence...</p>
              <p className="opacity-70">Target: {status.target}</p>
              <div className="h-px bg-slate-700 my-2"></div>

              {status.current_test && (
                <p className="text-yellow-300 animate-pulse">
                  <span className="mr-2">➤</span>
                  Running: {status.current_test}
                </p>
              )}

              {status.status === 'completed' && (
                <>
                  <div className="h-px bg-slate-700 my-2"></div>
                  <p className="text-blue-400 font-bold">✔ Scan Completed Successfully.</p>
                  <p className="text-white">Total Findings: {status.results?.length || 0}</p>
                </>
              )}
              {status.status === 'error' && (
                <>
                  <div className="h-px bg-slate-700 my-2"></div>
                  <p className="text-red-500 font-bold">✖ Process Failed.</p>
                  <p className="text-red-300">Error: {status.error}</p>
                </>
              )}
            </div>
          </div>

          {status.status === 'completed' && status.results && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
              <div className="p-4 bg-red-50 border border-red-100 rounded-lg text-center">
                <p className="text-xs uppercase tracking-wider text-red-600 font-bold mb-1">Critical</p>
                <p className="text-3xl font-black text-red-700">
                  {status.results.filter((r: any) =>
                    (r.severity === 'HIGH' || r.severity === 'CRITICAL' || r.severity === 'high' || r.severity === 'critical' || r.severity === '상')
                  ).length}
                </p>
              </div>
              <div className="p-4 bg-orange-50 border border-orange-100 rounded-lg text-center">
                <p className="text-xs uppercase tracking-wider text-orange-600 font-bold mb-1">Warning</p>
                <p className="text-3xl font-black text-orange-700">
                  {status.results.filter((r: any) =>
                    (r.severity === 'MEDIUM' || r.severity === 'medium' || r.severity === '중')
                  ).length}
                </p>
              </div>
              <div className="p-4 bg-yellow-50 border border-yellow-100 rounded-lg text-center">
                <p className="text-xs uppercase tracking-wider text-yellow-600 font-bold mb-1">Info</p>
                <p className="text-3xl font-black text-yellow-700">
                  {status.results.filter((r: any) =>
                    (r.severity === 'LOW' || r.severity === 'low' || r.severity === '하' || r.severity === '정보' || r.severity === 'INFO')
                  ).length}
                </p>
              </div>
              <div className="p-4 bg-slate-50 border border-slate-100 rounded-lg text-center">
                <p className="text-xs uppercase tracking-wider text-slate-600 font-bold mb-1">Total</p>
                <p className="text-3xl font-black text-slate-700">
                  {status.results.length}
                </p>
              </div>
            </div>
          )}

          {/* 성능 정보 표시 */}
          {status.status === 'completed' && status.metrics && (
            <div className="mt-6 p-4 bg-blue-50 border border-blue-100 rounded-lg">
              <h4 className="font-bold text-slate-800 mb-3 flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-blue-600" />
                스캔 성능 정보
              </h4>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <p className="text-slate-500 mb-1">스캔 소요 시간</p>
                  <p className="font-bold text-slate-900">
                    {status.metrics.scan_duration ? `${status.metrics.scan_duration.toFixed(2)}초` : 'N/A'}
                  </p>
                </div>
                <div>
                  <p className="text-slate-500 mb-1">실행된 테스트</p>
                  <p className="font-bold text-slate-900">
                    {status.metrics.scripts_executed || 0}개
                  </p>
                </div>
                <div>
                  <p className="text-slate-500 mb-1">건너뛴 테스트</p>
                  <p className="font-bold text-slate-900">
                    {status.metrics.scripts_skipped || 0}개
                  </p>
                </div>
                <div>
                  <p className="text-slate-500 mb-1">평균 응답 시간</p>
                  <p className="font-bold text-slate-900">
                    {status.metrics.avg_response_time ? `${status.metrics.avg_response_time.toFixed(3)}초` : 'N/A'}
                  </p>
                </div>
              </div>
              {status.results && (
                <div className="mt-3 pt-3 border-t border-blue-200">
                  <p className="text-sm text-slate-600">
                    <span className="font-semibold">전체 페이로드:</span> {status.results.length}개
                  </p>
                </div>
              )}
            </div>
          )}
        </CardContent>

        <CardFooter className="flex justify-between bg-slate-50/50 p-6 rounded-b-xl">
          <Button variant="outline" onClick={onBack} size="lg" className="bg-white hover:bg-slate-50">
            <ArrowLeft className="mr-2 h-4 w-4" />
            대시보드로 복귀
          </Button>

          <div className="flex gap-2">
            {status.status === 'completed' && status.report_path && (
              <Button
                className="bg-slate-900 hover:bg-slate-800"
                size="lg"
                onClick={handleViewReport}
                disabled={loadingReport}
              >
                {loadingReport ? (
                  <><Loader2 className="mr-2 h-4 w-4 animate-spin" />로딩 중...</>
                ) : (
                  <><FileText className="mr-2 h-4 w-4" />상세 리포트 보기</>
                )}
              </Button>
            )}
          </div>
        </CardFooter>
      </Card>

      {/* 마크다운 리포트 표시 */}
      {reportContent && (
        <Card className="border-slate-200 shadow-md mt-6">
          <CardHeader className="bg-slate-50/50 border-b border-slate-100">
            <CardTitle className="text-xl flex items-center gap-2">
              <FileText className="w-5 h-5 text-blue-600" />
              상세 보고서
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6">
            <div className="prose prose-slate max-w-none">
              <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                rehypePlugins={[rehypeRaw]}
              >
                {reportContent}
              </ReactMarkdown>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function HistoryView() {
  const [history, setHistory] = useState<HistoryItem[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedReport, setSelectedReport] = useState<string | null>(null)
  const [reportContent, setReportContent] = useState<string>("")
  const [reportLoading, setReportLoading] = useState(false)

  const handleViewReport = async (scanId: string) => {
    setReportLoading(true)
    setSelectedReport(scanId)
    try {
      const res = await fetch(`/api/report/raw/${scanId}`)
      if (res.ok) {
        const data = await res.json()
        setReportContent(data.content || "")
      }
    } catch (e) {
      console.error("Failed to fetch report", e)
      setReportContent("리포트를 불러오는데 실패했습니다.")
    } finally {
      setReportLoading(false)
    }
  }

  const fetchHistory = async () => {
    setLoading(true)
    try {
      const res = await fetch('/api/scans/history')
      if (res.ok) {
        const data = await res.json()
        setHistory(data.scans)
      }
    } catch (e) {
      console.error("Failed to fetch history", e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchHistory()
  }, [])

  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <div>
          <CardTitle>진단 이력</CardTitle>
          <CardDescription>과거 수행된 모든 보안 진단 기록입니다.</CardDescription>
        </div>
        <Button variant="outline" size="sm" onClick={fetchHistory}>
          <History className="w-4 h-4 mr-2" /> 새로고침
        </Button>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="text-center py-20">
            <Loader2 className="animate-spin w-8 h-8 mx-auto text-slate-400 mb-2" />
            <p className="text-slate-500">기록을 불러오는 중입니다...</p>
          </div>
        ) : (
          <div className="rounded-lg border border-slate-200 overflow-hidden">
            <table className="w-full text-sm text-left">
              <thead className="bg-slate-50 text-slate-600 font-semibold border-b border-slate-200">
                <tr>
                  <th className="p-4 w-[180px]">날짜</th>
                  <th className="p-4">대상</th>
                  <th className="p-4 w-[100px]">유형</th>
                  <th className="p-4 w-[120px]">상태</th>
                  <th className="p-4 text-right w-[100px]">취약점</th>
                  <th className="p-4 text-center w-[100px]">액션</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 bg-white">
                {history.length > 0 ? history.map((item) => (
                  <tr key={item.scan_id} className="hover:bg-slate-50 transition-colors">
                    <td className="p-4 text-slate-600">
                      {new Date(item.started_at).toLocaleDateString()}
                      <div className="text-xs text-slate-400 mt-0.5">{new Date(item.started_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div>
                    </td>
                    <td className="p-4 font-medium text-slate-900">{item.target}</td>
                    <td className="p-4">
                      {item.type === 'web' ?
                        <Badge variant="secondary" className="bg-blue-50 text-blue-700 hover:bg-blue-100">Web</Badge> :
                        <Badge variant="secondary" className="bg-slate-100 text-slate-700 hover:bg-slate-200">Infra</Badge>
                      }
                    </td>
                    <td className="p-4">
                      {item.status === 'completed' ?
                        <div className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-50 text-green-700 border border-green-100">
                          <CheckCircle2 className="w-3 h-3 mr-1" />완료
                        </div> :
                        (item.status === 'running' ?
                          <div className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-50 text-blue-700 border border-blue-100">
                            <Loader2 className="w-3 h-3 mr-1 animate-spin" />진행중
                          </div> :
                          <div className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-50 text-red-700 border border-red-100">
                            <XCircle className="w-3 h-3 mr-1" />실패
                          </div>
                        )
                      }
                    </td>
                    <td className="p-4 text-right">
                      <span className={`font-bold ${Number(item.summary.vulnerable) > 0 ? 'text-red-600' : 'text-slate-400'}`}>
                        {item.status === 'completed' ? (item.summary.vulnerable || '0') : '-'}
                      </span>
                    </td>
                    <td className="p-4 text-center">
                      {item.status === 'completed' && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleViewReport(item.scan_id)}
                        >
                          <FileText className="w-4 h-4 mr-1" />
                          보기
                        </Button>
                      )}
                    </td>
                  </tr>
                )) : (
                  <tr>
                    <td colSpan={6} className="text-center py-16 text-slate-400">
                      <History className="w-12 h-12 mx-auto mb-3 opacity-10" />
                      <p>수행된 진단 기록이 없습니다.</p>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>

      {/* 리포트 모달 */}
      <Dialog open={selectedReport !== null} onOpenChange={() => setSelectedReport(null)}>
        <DialogContent className="!max-w-7xl max-h-[85vh] overflow-y-auto w-[95vw]">
          <DialogHeader>
            <DialogTitle>진단 보고서</DialogTitle>
            <DialogDescription>
              Scan ID: {selectedReport}
            </DialogDescription>
          </DialogHeader>
          {reportLoading ? (
            <div className="flex justify-center p-8">
              <Loader2 className="animate-spin w-8 h-8 text-blue-600" />
            </div>
          ) : (
            <div className="prose prose-slate max-w-none">
              <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                rehypePlugins={[rehypeRaw]}
              >
                {reportContent}
              </ReactMarkdown>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </Card>
  )
}

function DashboardContent() {
  const [activeTab, setActiveTab] = useState("web")
  const [viewState, setViewState] = useState<'dashboard' | 'progress'>('dashboard')
  const [currentScanId, setCurrentScanId] = useState<string>("")

  // Form States
  const [webUrl, setWebUrl] = useState("")
  const [serverType, setServerType] = useState<string>("")
  const [serverAddress, setServerAddress] = useState("")
  const [sshUser, setSshUser] = useState("")
  const [sshPort, setSshPort] = useState("22")
  const [authMethod, setAuthMethod] = useState("password")
  const [sshPass, setSshPass] = useState("")
  const [pemFile, setPemFile] = useState<File | null>(null)

  const [isLoading, setIsLoading] = useState(false)
  const [backendStatus, setBackendStatus] = useState<boolean | null>(null)

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch('/api/health')
        setBackendStatus(res.ok)
      } catch (err) {
        setBackendStatus(false)
      }
    }
    checkHealth()
  }, [])

  const handleInfraScan = async () => {
    if (!serverAddress || !serverType || !sshUser) {
      alert("모든 필수 정보를 입력해주세요")
      return
    }

    setIsLoading(true)
    try {
      let endpoint = '/api/infra/scan/start'
      let body: any = null
      let headers: Record<string, string> = {}

      if (authMethod === 'key') {
        if (!pemFile) {
          alert("PEM 파일이 선택되지 않았습니다.")
          setIsLoading(false)
          return
        }
        endpoint = '/api/infra/scan/start/pem'
        const formData = new FormData()
        formData.append('ssh_host', serverAddress)
        formData.append('ssh_user', sshUser)
        formData.append('ssh_port', sshPort)
        formData.append('categories', JSON.stringify(['all']))
        formData.append('pem_file', pemFile)
        body = formData
      } else {
        if (!sshPass) {
          alert("SSH 비밀번호가 입력되지 않았습니다.")
          setIsLoading(false)
          return
        }
        headers['Content-Type'] = 'application/json'
        body = JSON.stringify({
          ssh_host: serverAddress,
          ssh_user: sshUser,
          ssh_pass: sshPass,
          ssh_port: parseInt(sshPort),
          categories: ['all']
        })
      }

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: headers,
        body: body
      })

      const data = await response.json()
      if (data.success) {
        setCurrentScanId(data.scan_id)
        setViewState('progress')
      } else {
        alert(`스캔 시작 실패: ${data.error || '알 수 없는 오류'}`)
      }
    } catch (error) {
      console.error("Scan error:", error)
      alert("진단 요청 중 오류가 발생했습니다.")
    } finally {
      setIsLoading(false)
    }
  }

  const handleWebScan = async () => {
    if (!webUrl) {
      alert("URL을 입력해주세요")
      return
    }

    setIsLoading(true)
    try {
      const response = await fetch('/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: webUrl,
          scan_types: ['all'],
          use_infra_detection: true
        }),
      })

      const data = await response.json()
      if (data.success) {
        setCurrentScanId(data.scan_id)
        setViewState('progress')
      } else {
        alert("스캔 시작에 실패했습니다: " + data.error)
      }
    } catch (error) {
      console.error(error)
      alert("서버 연결에 실패했습니다")
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-white p-6 md:p-10 font-[family-name:var(--font-pretendard)]">
      <div className="max-w-[1400px] mx-auto space-y-8">

        {/* Header Section */}
        <div className="flex justify-between items-start mb-8">
          <div className="space-y-2 cursor-pointer" onClick={() => setViewState('dashboard')}>
            <h1 className="text-3xl font-bold tracking-tight text-slate-900">보안 취약점 진단</h1>
            <p className="text-slate-500">웹 애플리케이션 및 인프라 서버에 대한 종합적인 보안 취약점 스캐닝</p>
          </div>

          <div className="flex gap-2">
            {backendStatus === true && (
              <Badge variant="outline" className="text-green-600 border-green-200 bg-green-50">
                <Wifi className="w-3 h-3 mr-1" /> 온라인
              </Badge>
            )}
            {backendStatus === false && (
              <Badge variant="outline" className="text-red-600 border-red-200 bg-red-50">
                <WifiOff className="w-3 h-3 mr-1" /> 연결 끊김
              </Badge>
            )}
          </div>
        </div>

        {/* Feature Cards */}
        <FeatureCards />

        {/* Main Interface */}
        {viewState === 'progress' ? (
          /* Progress View - Takes up the main content area */
          <ProgressView scanId={currentScanId} onBack={() => { setViewState('dashboard'); setActiveTab('history'); }} />
        ) : (
          /* Dashboard View - Tabs and Inputs */
          <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full space-y-8">
            <TabsList className="bg-slate-100 p-1 rounded-lg w-auto inline-flex h-auto">
              <TabsTrigger value="web" className="px-6 py-2.5 text-sm font-medium data-[state=active]:bg-white data-[state=active]:text-blue-600 data-[state=active]:shadow-sm rounded-md transition-all">
                <Globe className="w-4 h-4 mr-2" /> 웹 스캔
              </TabsTrigger>
              <TabsTrigger value="infra" className="px-6 py-2.5 text-sm font-medium data-[state=active]:bg-white data-[state=active]:text-slate-900 data-[state=active]:shadow-sm rounded-md transition-all">
                <Server className="w-4 h-4 mr-2" /> 인프라 진단
              </TabsTrigger>
              <TabsTrigger value="history" className="px-6 py-2.5 text-sm font-medium data-[state=active]:bg-white data-[state=active]:text-slate-900 data-[state=active]:shadow-sm rounded-md transition-all">
                <History className="w-4 h-4 mr-2" /> 진단 기록
              </TabsTrigger>
            </TabsList>

            {/* Web Scan Tab */}
            <TabsContent value="web" className="animate-in fade-in slide-in-from-bottom-2 duration-300">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Input Area (Left 2/3) */}
                <Card className="lg:col-span-2 border-slate-200 shadow-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Search className="w-5 h-5 text-blue-500" />
                      웹 애플리케이션 스캔
                    </CardTitle>
                    <CardDescription>웹 애플리케이션의 보안 취약점, 설정 오류, 컴플라이언스 문제를 분석합니다</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <div className="space-y-2">
                      <Label htmlFor="web-url">대상 URL</Label>
                      <Input
                        id="web-url"
                        placeholder="https://example.com"
                        className="h-14 text-lg bg-slate-50 border-slate-200"
                        value={webUrl}
                        onChange={(e) => setWebUrl(e.target.value)}
                      />
                    </div>
                    <Button
                      className="w-full h-14 text-lg font-bold bg-blue-600 hover:bg-blue-700"
                      onClick={handleWebScan}
                      disabled={isLoading}
                    >
                      {isLoading ? <><Loader2 className="mr-2 h-5 w-5 animate-spin" />스캔 시작 중...</> : '웹 스캔 시작'}
                    </Button>
                  </CardContent>
                </Card>

                {/* Info sidebar (Right 1/3) */}
                <div className="h-full">
                  <ScanInfoSidebar />
                </div>
              </div>
            </TabsContent>

            {/* Infra Scan Tab */}
            <TabsContent value="infra" className="animate-in fade-in slide-in-from-bottom-2 duration-300">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <Card className="lg:col-span-2 border-slate-200 shadow-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Server className="w-5 h-5 text-slate-700" />
                      서버 인프라 진단
                    </CardTitle>
                    <CardDescription>SSH 접속을 통해 서버 OS 및 서비스 설정 취약점을 정밀 점검합니다</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>서버 선택</Label>
                        <Select value={serverType} onValueChange={setServerType}>
                          <SelectTrigger className="h-12 bg-slate-50">
                            <SelectValue placeholder="서버 타입 선택" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="web">WEB</SelectItem>
                            <SelectItem value="was">WAS</SelectItem>
                            <SelectItem value="db">DB</SelectItem>
                            <SelectItem value="single">Single Server</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-2">
                        <Label>서버 주소 (IP)</Label>
                        <Input
                          placeholder="192.168.0.1"
                          className="h-12 bg-slate-50 font-mono"
                          value={serverAddress}
                          onChange={(e) => setServerAddress(e.target.value)}
                        />
                      </div>
                    </div>

                    <div className="p-4 bg-slate-50 rounded-lg border border-slate-100 space-y-4">
                      <div className="grid grid-cols-3 gap-4">
                        <div className="col-span-2 space-y-2">
                          <Label>SSH 사용자</Label>
                          <Input placeholder="root / ec2-user" className="bg-white" value={sshUser} onChange={(e) => setSshUser(e.target.value)} />
                        </div>
                        <div className="space-y-2">
                          <Label>포트</Label>
                          <Input placeholder="22" className="bg-white font-mono" value={sshPort} onChange={(e) => setSshPort(e.target.value)} />
                        </div>
                      </div>

                      <Tabs value={authMethod} onValueChange={setAuthMethod} className="w-full">
                        <TabsList className="grid w-full grid-cols-2 h-9 mb-2">
                          <TabsTrigger value="password" className="text-xs">비밀번호</TabsTrigger>
                          <TabsTrigger value="key" className="text-xs">키 파일</TabsTrigger>
                        </TabsList>
                        <TabsContent value="password">
                          <Input type="password" placeholder="SSH Password" className="bg-white" value={sshPass} onChange={(e) => setSshPass(e.target.value)} />
                        </TabsContent>
                        <TabsContent value="key">
                          <Input type="file" className="bg-white pt-2" onChange={(e) => { if (e.target.files) setPemFile(e.target.files[0]) }} />
                        </TabsContent>
                      </Tabs>
                    </div>

                    <Button
                      className="w-full h-14 text-lg font-bold bg-slate-800 hover:bg-slate-900"
                      onClick={handleInfraScan}
                      disabled={isLoading}
                    >
                      {isLoading ? <><Loader2 className="mr-2 h-5 w-5 animate-spin" />접속 중...</> : '인프라 진단 시작'}
                    </Button>
                  </CardContent>
                </Card>

                <div className="h-full">
                  <ScanInfoSidebar />
                </div>
              </div>
            </TabsContent>

            {/* History Tab */}
            <TabsContent value="history" className="animate-in fade-in slide-in-from-bottom-2 duration-300">
              <HistoryView />
            </TabsContent>
          </Tabs>
        )}
      </div>
    </div>
  )
}

export default function ScannerDashboard() {
  return (
    <Suspense fallback={<div className="flex h-screen items-center justify-center"><Loader2 className="animate-spin w-10 h-10 text-blue-600" /></div>}>
      <DashboardContent />
    </Suspense>
  )
}
