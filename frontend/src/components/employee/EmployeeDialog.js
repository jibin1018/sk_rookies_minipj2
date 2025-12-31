// src/components/employee/EmployeeDialog.jsx

import { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Button,
  Grid,
  MenuItem,
  Alert,
} from '@mui/material';

const EmployeeDialog = ({ open, onClose, employee, onSave, departments, teams }) => {
  const [formData, setFormData] = useState({
    employeeId: '',
    password: '',
    name: '',
    email: '',
    departmentId: '',
    teamId: '',
    position: '',
    role: 'USER',
    hireDate: new Date().toISOString().split('T')[0],
    phone: '',
  });
  const [error, setError] = useState('');

  useEffect(() => {
    if (employee) {
      // 수정 모드
      setFormData({
        employeeId: employee.employeeId || '',
        password: '', // 비밀번호는 수정 시 입력하지 않음
        name: employee.name || '',
        email: employee.email || '',
        departmentId: employee.departmentId || '',
        teamId: employee.teamId || '',
        position: employee.position || '',
        role: employee.role || 'USER',
        hireDate: employee.hireDate || new Date().toISOString().split('T')[0],
        phone: employee.phone || '',
      });
    } else {
      // 생성 모드
      setFormData({
        employeeId: '',
        password: '',
        name: '',
        email: '',
        departmentId: '',
        teamId: '',
        position: '',
        role: 'USER',
        hireDate: new Date().toISOString().split('T')[0],
        phone: '',
      });
    }
    setError('');
  }, [employee, open]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSubmit = async () => {
    try {
      setError('');

      // 생성 모드일 때만 비밀번호 필수
      if (!employee && !formData.password) {
        setError('비밀번호는 필수입니다');
        return;
      }

      await onSave(formData);
      onClose();
    } catch (err) {
      setError(err.response?.data?.message || '저장에 실패했습니다');
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>{employee ? '사원 정보 수정' : '사원 추가'}</DialogTitle>
      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Grid container spacing={2} sx={{ mt: 1 }}>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="사번"
              name="employeeId"
              value={formData.employeeId}
              onChange={handleChange}
              disabled={!!employee} // 수정 시 사번 변경 불가
              required
            />
          </Grid>

          {!employee && (
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="비밀번호"
                name="password"
                type="password"
                value={formData.password}
                onChange={handleChange}
                required
                helperText="초기 비밀번호를 입력하세요"
              />
            </Grid>
          )}

          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="이름"
              name="name"
              value={formData.name}
              onChange={handleChange}
              required
            />
          </Grid>

          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="이메일"
              name="email"
              type="email"
              value={formData.email}
              onChange={handleChange}
              required
            />
          </Grid>

          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              select
              label="부서"
              name="departmentId"
              value={formData.departmentId}
              onChange={handleChange}
              required
            >
              {departments.map((dept) => (
                <MenuItem key={dept.id} value={dept.id}>
                  {dept.name}
                </MenuItem>
              ))}
            </TextField>
          </Grid>

          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              select
              label="팀"
              name="teamId"
              value={formData.teamId}
              onChange={handleChange}
            >
              <MenuItem value="">없음</MenuItem>
              {teams
                .filter((team) => team.departmentId === formData.departmentId)
                .map((team) => (
                  <MenuItem key={team.id} value={team.id}>
                    {team.name}
                  </MenuItem>
                ))}
            </TextField>
          </Grid>

          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="직급"
              name="position"
              value={formData.position}
              onChange={handleChange}
              required
            />
          </Grid>

          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              select
              label="역할"
              name="role"
              value={formData.role}
              onChange={handleChange}
              required
            >
              <MenuItem value="USER">사원</MenuItem>
              <MenuItem value="MANAGER">팀장</MenuItem>
              <MenuItem value="ADMIN">관리자</MenuItem>
            </TextField>
          </Grid>

          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="입사일"
              name="hireDate"
              type="date"
              value={formData.hireDate}
              onChange={handleChange}
              InputLabelProps={{ shrink: true }}
              required
            />
          </Grid>

          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="전화번호"
              name="phone"
              value={formData.phone}
              onChange={handleChange}
            />
          </Grid>
        </Grid>
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose}>취소</Button>
        <Button onClick={handleSubmit} variant="contained">
          {employee ? '수정' : '추가'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default EmployeeDialog;