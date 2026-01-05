// src/components/employee/EmployeeDialog.js

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
import enumService from '../../services/enumService';

const EmployeeDialog = ({ open, onClose, employee, onSave, departments, teams }) => {
  const [formData, setFormData] = useState({
    employeeId: '',
    password: '',
    name: '',
    email: '',
    departmentId: '',
    teamId: '',
    position: '',
    role: '',
    hireDate: new Date().toISOString().split('T')[0],
    phone: '',
  });
  const [positions, setPositions] = useState([]);
  const [roles, setRoles] = useState([]);
  const [error, setError] = useState('');

  // Enum 데이터 로드
  useEffect(() => {
    const fetchEnums = async () => {
      try {
        const [positionsRes, rolesRes] = await Promise.all([
          enumService.getPositions(),
          enumService.getRoles(),
        ]);
        setPositions(positionsRes.data || []);
        setRoles(rolesRes.data || []);
      } catch (err) {
        console.error('Enum 데이터 로드 실패:', err);
      }
    };

    if (open) {
      fetchEnums();
    }
  }, [open]);

  useEffect(() => {
    if (employee) {
      // 수정 모드
      setFormData({
        employeeId: employee.employeeId || '',
        password: '',
        name: employee.name || '',
        email: employee.email || '',
        departmentId: employee.departmentId || '',
        teamId: employee.teamId || '',
        position: employee.position || '',
        role: employee.role || '',
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
        role: '',
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

      // 필수 필드 검증
      if (!formData.position) {
        setError('직급을 선택해주세요');
        return;
      }

      if (!formData.role) {
        setError('역할을 선택해주세요');
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
      <DialogTitle 
        sx={{ 
          fontSize: '1.5rem', 
          fontWeight: 600, 
          color: '#37352f',
          borderBottom: '1px solid rgba(55, 53, 47, 0.09)',
          pb: 2
        }}
      >
        {employee ? '사원 정보 수정' : '사원 추가'}
      </DialogTitle>
      <DialogContent sx={{ pt: 3 }}>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="사번"
              name="employeeId"
              value={formData.employeeId}
              onChange={handleChange}
              disabled={!!employee}
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
              <MenuItem value="">선택하세요</MenuItem>
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
              select
              label="직급"
              name="position"
              value={formData.position}
              onChange={handleChange}
              required
            >
              <MenuItem value="">선택하세요</MenuItem>
              {positions.map((position) => (
                <MenuItem key={position.value} value={position.value}>
                  {position.label}
                </MenuItem>
              ))}
            </TextField>
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
              <MenuItem value="">선택하세요</MenuItem>
              {roles.map((role) => (
                <MenuItem key={role.value} value={role.value}>
                  {role.label}
                </MenuItem>
              ))}
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
              placeholder="010-1234-5678"
            />
          </Grid>
        </Grid>
      </DialogContent>

      <DialogActions sx={{ px: 3, py: 2, borderTop: '1px solid rgba(55, 53, 47, 0.09)' }}>
        <Button 
          onClick={onClose}
          sx={{ 
            color: '#787774',
            '&:hover': { backgroundColor: 'rgba(55, 53, 47, 0.08)' }
          }}
        >
          취소
        </Button>
        <Button 
          onClick={handleSubmit} 
          variant="contained"
          sx={{
            backgroundColor: '#37352f',
            '&:hover': { backgroundColor: '#2e2c28' }
          }}
        >
          {employee ? '수정' : '추가'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default EmployeeDialog;