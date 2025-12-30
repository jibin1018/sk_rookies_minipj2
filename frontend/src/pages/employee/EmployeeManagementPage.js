"use client"

import { useState, useEffect } from "react"
import {
  Box,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Chip,
  Button,
  Alert,
} from "@mui/material"
import { Delete, Edit, PersonAdd } from "@mui/icons-material"
import employeeService from "../../services/employeeService"

const EmployeeManagementPage = () => {
  console.log("[v0] EmployeeManagementPage - Component mounted")

  const [employees, setEmployees] = useState([])
  const [loading, setLoading] = useState(true)
  const [openDialog, setOpenDialog] = useState(false)
  const [selectedEmployee, setSelectedEmployee] = useState(null)
  const [error, setError] = useState("")
  const [success, setSuccess] = useState("")

  useEffect(() => {
    console.log("[v0] EmployeeManagementPage - useEffect triggered")
    fetchEmployees()
  }, [])

  const fetchEmployees = async () => {
    try {
      setLoading(true)
      console.log("[v0] EmployeeManagementPage - Fetching employees")
      const response = await employeeService.getAllEmployees()
      console.log("[v0] EmployeeManagementPage - Employees response:", response)
      setEmployees(response.data || [])
    } catch (error) {
      console.error("[v0] 사원 목록 조회 실패:", error)
      setError("사원 목록을 불러오는데 실패했습니다.")
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async (employeeId) => {
    if (!window.confirm("정말로 이 사원을 삭제하시겠습니까?")) {
      return
    }

    try {
      await employeeService.deleteEmployee(employeeId)
      setSuccess("사원이 삭제되었습니다.")
      fetchEmployees()
      setTimeout(() => setSuccess(""), 3000)
    } catch (error) {
      console.error("사원 삭제 실패:", error)
      setError("사원 삭제에 실패했습니다.")
      setTimeout(() => setError(""), 3000)
    }
  }

  const getRoleText = (role) => {
    const roleMap = {
      ADMIN: "관리자",
      TEAM_LEADER: "팀장",
      EMPLOYEE: "사원",
    }
    return roleMap[role] || role
  }

  const getRoleColor = (role) => {
    const colorMap = {
      ADMIN: "error",
      TEAM_LEADER: "warning",
      EMPLOYEE: "default",
    }
    return colorMap[role] || "default"
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 4 }}>
        <Typography
          variant="h4"
          sx={{
            fontWeight: 700,
            fontSize: "2rem",
            color: "#37352f",
            letterSpacing: "-0.01em",
          }}
        >
          사원 관리
        </Typography>
        <Button
          variant="contained"
          startIcon={<PersonAdd />}
          onClick={() => {
            setSelectedEmployee(null)
            setOpenDialog(true)
          }}
          sx={{
            backgroundColor: "#37352f",
            color: "#ffffff",
            px: 3,
            py: 1.25,
            fontSize: "1rem",
            fontWeight: 500,
            textTransform: "none",
            borderRadius: "6px",
            boxShadow: "rgba(15, 15, 15, 0.1) 0px 1px 2px",
            "&:hover": {
              backgroundColor: "#2e2c28",
              boxShadow: "rgba(15, 15, 15, 0.2) 0px 2px 4px",
            },
          }}
        >
          사원 추가
        </Button>
      </Box>

      {/* Alerts */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError("")}>
          {error}
        </Alert>
      )}
      {success && (
        <Alert severity="success" sx={{ mb: 3 }} onClose={() => setSuccess("")}>
          {success}
        </Alert>
      )}

      {/* Employee Table */}
      <TableContainer
        component={Paper}
        sx={{
          borderRadius: "8px",
          border: "1px solid rgba(55, 53, 47, 0.09)",
          boxShadow: "rgba(15, 15, 15, 0.03) 0px 1px 2px",
        }}
      >
        <Table>
          <TableHead>
            <TableRow>
              <TableCell sx={{ fontWeight: 600, fontSize: "1rem", color: "#37352f" }}>사번</TableCell>
              <TableCell sx={{ fontWeight: 600, fontSize: "1rem", color: "#37352f" }}>이름</TableCell>
              <TableCell sx={{ fontWeight: 600, fontSize: "1rem", color: "#37352f" }}>이메일</TableCell>
              <TableCell sx={{ fontWeight: 600, fontSize: "1rem", color: "#37352f" }}>부서</TableCell>
              <TableCell sx={{ fontWeight: 600, fontSize: "1rem", color: "#37352f" }}>직급</TableCell>
              <TableCell sx={{ fontWeight: 600, fontSize: "1rem", color: "#37352f" }}>역할</TableCell>
              <TableCell sx={{ fontWeight: 600, fontSize: "1rem", color: "#37352f" }} align="center">
                관리
              </TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={7} align="center" sx={{ py: 8 }}>
                  <Typography sx={{ color: "#787774" }}>로딩 중...</Typography>
                </TableCell>
              </TableRow>
            ) : employees.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} align="center" sx={{ py: 8 }}>
                  <Typography sx={{ color: "#787774" }}>등록된 사원이 없습니다.</Typography>
                </TableCell>
              </TableRow>
            ) : (
              employees.map((employee) => (
                <TableRow
                  key={employee.id}
                  sx={{
                    "&:hover": {
                      backgroundColor: "rgba(55, 53, 47, 0.03)",
                    },
                  }}
                >
                  <TableCell sx={{ fontSize: "1rem", color: "#37352f" }}>{employee.employeeId}</TableCell>
                  <TableCell sx={{ fontSize: "1rem", color: "#37352f", fontWeight: 500 }}>{employee.name}</TableCell>
                  <TableCell sx={{ fontSize: "1rem", color: "#787774" }}>{employee.email}</TableCell>
                  <TableCell sx={{ fontSize: "1rem", color: "#37352f" }}>{employee.department}</TableCell>
                  <TableCell sx={{ fontSize: "1rem", color: "#37352f" }}>{employee.position}</TableCell>
                  <TableCell>
                    <Chip
                      label={getRoleText(employee.role)}
                      color={getRoleColor(employee.role)}
                      size="small"
                      sx={{ fontWeight: 500 }}
                    />
                  </TableCell>
                  <TableCell align="center">
                    <IconButton
                      size="small"
                      onClick={() => {
                        setSelectedEmployee(employee)
                        setOpenDialog(true)
                      }}
                      sx={{
                        color: "#787774",
                        "&:hover": {
                          color: "#37352f",
                          backgroundColor: "rgba(55, 53, 47, 0.08)",
                        },
                      }}
                    >
                      <Edit fontSize="small" />
                    </IconButton>
                    <IconButton
                      size="small"
                      onClick={() => handleDelete(employee.id)}
                      sx={{
                        color: "#787774",
                        ml: 1,
                        "&:hover": {
                          color: "#dc2626",
                          backgroundColor: "rgba(220, 38, 38, 0.08)",
                        },
                      }}
                    >
                      <Delete fontSize="small" />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  )
}

export default EmployeeManagementPage
