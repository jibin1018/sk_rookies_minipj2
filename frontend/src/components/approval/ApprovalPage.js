"use client"

import { useState, useEffect } from "react"
import {
  Container,
  Paper,
  Typography,
  Button,
  Box,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Stepper,
  Step,
  StepLabel,
} from "@mui/material"
import { Add, Check, Close } from "@mui/icons-material"
import { useAuth } from "../../contexts/AuthContext"
import approvalService from "../../services/approvalService"
import employeeService from "../../services/employeeService"

const ApprovalPage = () => {
  const { user } = useAuth()
  const [tabValue, setTabValue] = useState(0)
  const [myApprovals, setMyApprovals] = useState([])
  const [pendingApprovals, setPendingApprovals] = useState([])
  const [dialogOpen, setDialogOpen] = useState(false)
  const [detailDialogOpen, setDetailDialogOpen] = useState(false)
  const [selectedApproval, setSelectedApproval] = useState(null)
  const [employees, setEmployees] = useState([])

  const [formData, setFormData] = useState({
    documentType: "휴가신청서",
    title: "",
    content: "",
    approverIds: [],
  })

  useEffect(() => {
    fetchMyApprovals()
    fetchPendingApprovals()
    fetchEmployees()
  }, [])

  const fetchMyApprovals = async () => {
    try {
      console.log("내 결재 문서 조회 시작")
      const response = await approvalService.getMyApprovals(0, 20)
      console.log("내 결재 문서 응답:", response)

      if (response.success) {
        setMyApprovals(response.data.content || response.data)
      }
    } catch (error) {
      console.error("내 결재 문서 조회 실패:", error)
    }
  }

  const fetchPendingApprovals = async () => {
    try {
      console.log("결재 대기 문서 조회 시작")
      const response = await approvalService.getPendingApprovals()
      console.log("결재 대기 문서 응답:", response)

      if (response.success) {
        console.log("결재 대기 문서 개수:", response.data.length)
        setPendingApprovals(response.data)
      }
    } catch (error) {
      console.error("결재 대기 문서 조회 실패:", error)
    }
  }

  const fetchEmployees = async () => {
    try {
      const response = await employeeService.getAllEmployees()
      if (response.success) {
        const otherEmployees = response.data.filter((emp) => emp.id !== user?.id)
        setEmployees(otherEmployees)
      }
    } catch (error) {
      console.error("사원 목록 조회 실패:", error)
    }
  }

  const handleSubmit = async () => {
    if (!formData.title || !formData.content || formData.approverIds.length === 0) {
      alert("필수 항목을 입력하세요")
      return
    }

    try {
      console.log("결재 상신 데이터:", formData)
      const response = await approvalService.createApproval(formData)
      console.log("결재 상신 응답:", response)

      if (response.success) {
        alert("결재가 상신되었습니다")
        setDialogOpen(false)
        setFormData({
          documentType: "휴가신청서",
          title: "",
          content: "",
          approverIds: [],
        })
        fetchMyApprovals()
      }
    } catch (error) {
      console.error("결재 상신 실패:", error)
      alert(error.response?.data?.message || "결재 상신에 실패했습니다")
    }
  }

  const handleViewDetail = async (approvalId) => {
    try {
      console.log("상세보기 클릭 - ID:", approvalId)
      const response = await approvalService.getApproval(approvalId)
      console.log("상세 응답:", response)

      if (response.success) {
        setSelectedApproval(response.data)
        setDetailDialogOpen(true)
      }
    } catch (error) {
      console.error("결재 상세 조회 실패:", error)
      alert("상세 정보를 불러올 수 없습니다")
    }
  }

  const handleProcess = async (approvalId, action) => {
    const comment = window.prompt(action === "APPROVE" ? "승인 의견을 입력하세요 (선택사항)" : "반려 사유를 입력하세요")

    if (action === "REJECT" && !comment) {
      alert("반려 사유를 입력해야 합니다")
      return
    }

    try {
      const response = await approvalService.processApproval(approvalId, action, comment)
      if (response.success) {
        alert(action === "APPROVE" ? "승인되었습니다" : "반려되었습니다")
        setDetailDialogOpen(false)
        fetchMyApprovals()
        fetchPendingApprovals()
      }
    } catch (error) {
      console.error("결재 처리 실패:", error)
      alert(error.response?.data?.message || "결재 처리에 실패했습니다")
    }
  }

  const getStatusColor = (status) => {
    const colors = {
      PENDING: "default",
      IN_PROGRESS: "primary",
      APPROVED: "success",
      REJECTED: "error",
      CANCELLED: "warning",
    }
    return colors[status] || "default"
  }

  const getStatusLabel = (status) => {
    const labels = {
      PENDING: "대기",
      IN_PROGRESS: "진행중",
      APPROVED: "승인",
      REJECTED: "반려",
      CANCELLED: "취소",
    }
    return labels[status] || status
  }

  const formatDate = (dateString) => {
    const date = new Date(dateString)
    return date.toLocaleDateString("ko-KR")
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 2, mb: 4 }}>
      <Box sx={{ mb: 5 }}>
        <Typography variant="h4" sx={{ mb: 1, fontWeight: 700, fontSize: "2.5rem" }}>
          전자결재
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ fontSize: "1.125rem" }}>
          결재 문서를 관리하고 처리하세요
        </Typography>
      </Box>

      <Box
        sx={{
          mb: 4,
          display: "flex",
          gap: 1,
          borderBottom: "1px solid rgba(55, 53, 47, 0.09)",
        }}
      >
        <Button
          variant={tabValue === 0 ? "contained" : "text"}
          onClick={() => setTabValue(0)}
          sx={{
            borderRadius: "8px 8px 0 0",
            fontSize: "1rem",
            fontWeight: 500,
            px: 3,
            py: 1.5,
            ...(tabValue === 0
              ? {
                  bgcolor: "#37352f",
                  color: "#ffffff",
                  "&:hover": { bgcolor: "#2c2a27" },
                }
              : {
                  color: "text.secondary",
                  "&:hover": { bgcolor: "rgba(55, 53, 47, 0.03)" },
                }),
          }}
        >
          내 결재 문서
        </Button>
        <Button
          variant={tabValue === 1 ? "contained" : "text"}
          onClick={() => setTabValue(1)}
          sx={{
            borderRadius: "8px 8px 0 0",
            fontSize: "1rem",
            fontWeight: 500,
            px: 3,
            py: 1.5,
            ...(tabValue === 1
              ? {
                  bgcolor: "#37352f",
                  color: "#ffffff",
                  "&:hover": { bgcolor: "#2c2a27" },
                }
              : {
                  color: "text.secondary",
                  "&:hover": { bgcolor: "rgba(55, 53, 47, 0.03)" },
                }),
          }}
        >
          결재 대기 ({pendingApprovals.length})
        </Button>
        <Box sx={{ flexGrow: 1 }} />
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={() => setDialogOpen(true)}
          sx={{
            bgcolor: "#37352f",
            fontSize: "1rem",
            color: "#ffffff",
            "&:hover": { bgcolor: "#2c2a27" },
          }}
        >
          결재 상신
        </Button>
      </Box>

      <Box>
        {tabValue === 0 && (
          <Box>
            {myApprovals.length === 0 ? (
              <Box sx={{ p: 6, textAlign: "center", color: "text.secondary" }}>
                <Typography sx={{ fontSize: "1.125rem" }}>결재 문서가 없습니다</Typography>
              </Box>
            ) : (
              <Box sx={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: 3 }}>
                {myApprovals.map((approval) => (
                  <Box
                    key={approval.id}
                    onClick={() => handleViewDetail(approval.id)}
                    sx={{
                      p: 3,
                      border: "1px solid rgba(55, 53, 47, 0.09)",
                      borderRadius: 2,
                      cursor: "pointer",
                      transition: "all 0.2s",
                      "&:hover": {
                        boxShadow: "rgba(15, 15, 15, 0.1) 0px 3px 6px, rgba(15, 15, 15, 0.2) 0px 9px 24px",
                        transform: "translateY(-2px)",
                      },
                    }}
                  >
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "start", mb: 2 }}>
                      <Chip
                        label={approval.documentType}
                        size="small"
                        sx={{
                          height: "24px",
                          fontSize: "0.875rem",
                          backgroundColor: "rgba(55, 53, 47, 0.08)",
                          color: "#37352f",
                        }}
                      />
                      <Chip
                        label={getStatusLabel(approval.status)}
                        size="small"
                        sx={{
                          height: "24px",
                          fontSize: "0.875rem",
                          fontWeight: 500,
                          ...(approval.status === "APPROVED" && { bgcolor: "#dcfce7", color: "#16a34a" }),
                          ...(approval.status === "REJECTED" && { bgcolor: "#fee2e2", color: "#dc2626" }),
                          ...(approval.status === "PENDING" && { bgcolor: "#f3f4f6", color: "#6b7280" }),
                          ...(approval.status === "IN_PROGRESS" && { bgcolor: "#dbeafe", color: "#0284c7" }),
                        }}
                      />
                    </Box>
                    <Typography variant="h6" sx={{ mb: 1.5, fontWeight: 600, fontSize: "1.125rem" }}>
                      {approval.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5, fontSize: "0.9375rem" }}>
                      요청자: {approval.requesterName}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.875rem" }}>
                      {formatDate(approval.createdAt)}
                    </Typography>
                  </Box>
                ))}
              </Box>
            )}
          </Box>
        )}

        {tabValue === 1 && (
          <Box>
            {pendingApprovals.length === 0 ? (
              <Box sx={{ p: 6, textAlign: "center", color: "text.secondary" }}>
                <Typography sx={{ fontSize: "1.125rem" }}>결재 대기 문서가 없습니다</Typography>
              </Box>
            ) : (
              <Box sx={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: 3 }}>
                {pendingApprovals.map((approval) => (
                  <Box
                    key={approval.id}
                    onClick={() => handleViewDetail(approval.id)}
                    sx={{
                      p: 3,
                      border: "1px solid rgba(15, 98, 254, 0.2)",
                      borderRadius: 2,
                      cursor: "pointer",
                      backgroundColor: "rgba(15, 98, 254, 0.02)",
                      transition: "all 0.2s",
                      "&:hover": {
                        boxShadow: "rgba(15, 15, 15, 0.1) 0px 3px 6px, rgba(15, 15, 15, 0.2) 0px 9px 24px",
                        transform: "translateY(-2px)",
                      },
                    }}
                  >
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "start", mb: 2 }}>
                      <Chip
                        label={approval.documentType}
                        size="small"
                        sx={{
                          height: "24px",
                          fontSize: "0.875rem",
                          backgroundColor: "rgba(55, 53, 47, 0.08)",
                          color: "#37352f",
                        }}
                      />
                      <Chip
                        label="결재 필요"
                        size="small"
                        sx={{
                          height: "24px",
                          fontSize: "0.875rem",
                          fontWeight: 600,
                          bgcolor: "#fef2f2",
                          color: "#dc2626",
                        }}
                      />
                    </Box>
                    <Typography variant="h6" sx={{ mb: 1.5, fontWeight: 600, fontSize: "1.125rem" }}>
                      {approval.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5, fontSize: "0.9375rem" }}>
                      요청자: {approval.requesterName}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.875rem" }}>
                      {formatDate(approval.createdAt)}
                    </Typography>
                  </Box>
                ))}
              </Box>
            )}
          </Box>
        )}
      </Box>

      {/* Dialogs remain similar with minor styling updates */}
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>결재 상신</DialogTitle>
        <DialogContent>
          <FormControl fullWidth sx={{ mt: 2, mb: 2 }}>
            <InputLabel>문서 종류</InputLabel>
            <Select
              value={formData.documentType}
              label="문서 종류"
              onChange={(e) => setFormData({ ...formData, documentType: e.target.value })}
            >
              <MenuItem value="휴가신청서">휴가신청서</MenuItem>
              <MenuItem value="지출결의서">지출결의서</MenuItem>
              <MenuItem value="구매요청서">구매요청서</MenuItem>
              <MenuItem value="업무보고서">업무보고서</MenuItem>
              <MenuItem value="기안서">기안서</MenuItem>
            </Select>
          </FormControl>

          <TextField
            fullWidth
            label="제목"
            value={formData.title}
            onChange={(e) => setFormData({ ...formData, title: e.target.value })}
            sx={{ mb: 2 }}
            required
          />

          <TextField
            fullWidth
            label="내용"
            multiline
            rows={6}
            value={formData.content}
            onChange={(e) => setFormData({ ...formData, content: e.target.value })}
            sx={{ mb: 2 }}
            required
          />

          <FormControl fullWidth>
            <InputLabel>결재자 선택 (순서대로)</InputLabel>
            <Select
              multiple
              value={formData.approverIds}
              label="결재자 선택 (순서대로)"
              onChange={(e) => setFormData({ ...formData, approverIds: e.target.value })}
              renderValue={(selected) => selected.map((id) => employees.find((emp) => emp.id === id)?.name).join(" → ")}
            >
              {employees.map((emp) => (
                <MenuItem key={emp.id} value={emp.id}>
                  {emp.name} ({emp.position}) - {emp.departmentName}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>취소</Button>
          <Button onClick={handleSubmit} variant="contained">
            상신
          </Button>
        </DialogActions>
      </Dialog>

      {/* 결재 상세 Dialog */}
      {selectedApproval && (
        <Dialog open={detailDialogOpen} onClose={() => setDetailDialogOpen(false)} maxWidth="md" fullWidth>
          <DialogTitle sx={{ fontSize: "1.5rem", fontWeight: 600 }}>결재 상세</DialogTitle>
          <DialogContent>
            <Box sx={{ mb: 3 }}>
              <Typography variant="h6" sx={{ fontSize: "1.25rem", fontWeight: 600 }}>
                {selectedApproval.title}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.9375rem", mt: 0.5 }}>
                문서 종류: {selectedApproval.documentType}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.9375rem" }}>
                요청자: {selectedApproval.requesterName}
              </Typography>
              <Chip
                label={getStatusLabel(selectedApproval.status)}
                color={getStatusColor(selectedApproval.status)}
                sx={{ mt: 1 }}
              />
            </Box>

            <Paper sx={{ p: 2, mb: 3, bgcolor: "grey.50" }}>
              <Typography variant="body1" whiteSpace="pre-wrap" sx={{ fontSize: "1rem", lineHeight: 1.7 }}>
                {selectedApproval.content}
              </Typography>
            </Paper>

            <Typography variant="h6" gutterBottom sx={{ fontSize: "1.125rem", fontWeight: 600 }}>
              결재선
            </Typography>
            <Stepper activeStep={selectedApproval.currentStep - 1} orientation="vertical">
              {selectedApproval.approvalLines.map((line) => (
                <Step key={line.id}>
                  <StepLabel
                    StepIconProps={{
                      sx: {
                        color:
                          line.status === "APPROVED"
                            ? "success.main"
                            : line.status === "REJECTED"
                              ? "error.main"
                              : undefined,
                      },
                    }}
                  >
                    <Box>
                      <Typography variant="body2" sx={{ fontSize: "1rem", fontWeight: 500 }}>
                        {line.approverName} ({line.stepOrder}차 결재자)
                      </Typography>
                      <Chip
                        label={getStatusLabel(line.status)}
                        color={getStatusColor(line.status)}
                        size="small"
                        sx={{ mt: 0.5 }}
                      />
                      {line.comment && (
                        <Typography
                          variant="body2"
                          display="block"
                          sx={{ mt: 1.5, fontSize: "1rem", lineHeight: 1.6, color: "#37352f" }}
                        >
                          의견: {line.comment}
                        </Typography>
                      )}
                    </Box>
                  </StepLabel>
                </Step>
              ))}
            </Stepper>
          </DialogContent>
          <DialogActions sx={{ p: 2.5 }}>
            {selectedApproval.approvalLines.some(
              (line) => line.approverId === user.id && line.status === "PENDING",
            ) && (
              <>
                <Button
                  startIcon={<Close />}
                  color="error"
                  onClick={() => handleProcess(selectedApproval.id, "REJECT")}
                  sx={{ fontSize: "1rem" }}
                >
                  반려
                </Button>
                <Button
                  startIcon={<Check />}
                  variant="contained"
                  onClick={() => handleProcess(selectedApproval.id, "APPROVE")}
                  sx={{
                    fontSize: "1rem",
                    bgcolor: "#37352f",
                    "&:hover": { bgcolor: "#2c2a27" },
                  }}
                >
                  승인
                </Button>
              </>
            )}
            <Button onClick={() => setDetailDialogOpen(false)} sx={{ fontSize: "1rem" }}>
              닫기
            </Button>
          </DialogActions>
        </Dialog>
      )}
    </Container>
  )
}

export default ApprovalPage
