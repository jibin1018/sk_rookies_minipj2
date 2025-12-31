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
import departmentService from "../../services/departmentService"
import teamService from "../../services/teamService"
import EmployeeDialog from "../../components/employee/EmployeeDialog"

const EmployeeManagementPage = () => {
  const [employees, setEmployees] = useState([])
  const [departments, setDepartments] = useState([])
  const [teams, setTeams] = useState([])
  const [loading, setLoading] = useState(true)
  const [openDialog, setOpenDialog] = useState(false)
  const [selectedEmployee, setSelectedEmployee] = useState(null)
  const [error, setError] = useState("")
  const [success, setSuccess] = useState("")

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    try {
      setLoading(true)
      const [employeesRes, departmentsRes, teamsRes] = await Promise.all([
        employeeService.getAllEmployees(),
        departmentService.getAllDepartments(),
        teamService.getAllTeams(),
      ])
      
      setEmployees(employeesRes.data || [])
      setDepartments(departmentsRes.data || [])
      setTeams(teamsRes.data || [])
    } catch (error) {
      console.error("데이터 조회 실패:", error)
      setError("데이터를 불러오는데 실패했습니다.")
    } finally {
      setLoading(false)
    }
  }

  const handleSave = async (formData) => {
    try {
      if (selectedEmployee) {
        // 수정
        await employeeService.updateEmployee(selectedEmployee.id, formData)
        setSuccess("사원 정보가 수정되었습니다.")
      } else {
        // 생성
        await employeeService.createEmployee(formData)
        setSuccess("사원이 추가되었습니다.")
      }
      
      fetchData()
      setOpenDialog(false)
      setTimeout(() => setSuccess(""), 3000)
    } catch (error) {
      throw error
    }
  }

  const handleDelete = async (employeeId) => {
    if (!window.confirm("정말로 이 사원을 삭제하시겠습니까?")) {
      return
    }

    try {
      await employeeService.deleteEmployee(employeeId)
      setSuccess("사원이 삭제되었습니다.")
      fetchData()
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
      MANAGER: "팀장",
      USER: "사원",
    }
    return roleMap[role] || role
  }

  const getRoleColor = (role) => {
    const colorMap = {
      ADMIN: "error",
      MANAGER: "warning",
      USER: "default",
    }
    return colorMap[role] || "default"
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 4 }}>
        <Typography variant="h4" sx={{ fontWeight: 700, fontSize: "2rem", color: "#37352f" }}>
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
            "&:hover": { backgroundColor: "#2e2c28" },
          }}
        >
          사원 추가
        </Button>
      </Box>

      {/* Alerts */}
      {error && <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError("")}>{error}</Alert>}
      {success && <Alert severity="success" sx={{ mb: 3 }} onClose={() => setSuccess("")}>{success}</Alert>}

      {/* Employee Table */}
      <TableContainer component={Paper} sx={{ borderRadius: "8px", border: "1px solid rgba(55, 53, 47, 0.09)" }}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell sx={{ fontWeight: 600 }}>사번</TableCell>
              <TableCell sx={{ fontWeight: 600 }}>이름</TableCell>
              <TableCell sx={{ fontWeight: 600 }}>이메일</TableCell>
              <TableCell sx={{ fontWeight: 600 }}>부서</TableCell>
              <TableCell sx={{ fontWeight: 600 }}>팀</TableCell>
              <TableCell sx={{ fontWeight: 600 }}>직급</TableCell>
              <TableCell sx={{ fontWeight: 600 }}>역할</TableCell>
              <TableCell sx={{ fontWeight: 600 }} align="center">관리</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={8} align="center" sx={{ py: 8 }}>로딩 중...</TableCell>
              </TableRow>
            ) : employees.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} align="center" sx={{ py: 8 }}>등록된 사원이 없습니다.</TableCell>
              </TableRow>
            ) : (
              employees.map((employee) => (
                <TableRow key={employee.id} sx={{ "&:hover": { backgroundColor: "rgba(55, 53, 47, 0.03)" } }}>
                  <TableCell>{employee.employeeId}</TableCell>
                  <TableCell sx={{ fontWeight: 500 }}>{employee.name}</TableCell>
                  <TableCell>{employee.email}</TableCell>
                  <TableCell>{employee.departmentName}</TableCell>
                  <TableCell>{employee.teamName || '-'}</TableCell>
                  <TableCell>{employee.position}</TableCell>
                  <TableCell>
                    <Chip label={getRoleText(employee.role)} color={getRoleColor(employee.role)} size="small" />
                  </TableCell>
                  <TableCell align="center">
                    <IconButton size="small" onClick={() => { setSelectedEmployee(employee); setOpenDialog(true); }}>
                      <Edit fontSize="small" />
                    </IconButton>
                    <IconButton size="small" onClick={() => handleDelete(employee.id)} sx={{ ml: 1 }}>
                      <Delete fontSize="small" />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Employee Dialog */}
      <EmployeeDialog
        open={openDialog}
        onClose={() => setOpenDialog(false)}
        employee={selectedEmployee}
        onSave={handleSave}
        departments={departments}
        teams={teams}
      />
    </Box>
  )
}

export default EmployeeManagementPage