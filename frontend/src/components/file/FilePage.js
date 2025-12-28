import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  Button,
  Box,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Input,
  TextField,
} from '@mui/material';
import { Upload, Download, Delete, Folder } from '@mui/icons-material';
import { useAuth } from '../../contexts/AuthContext';
import { useSecurityMode } from '../../contexts/SecurityModeContext';
import fileService from '../../services/fileService';

const FilePage = () => {
  const { user } = useAuth();
  const { isSecure } = useSecurityMode();
  const [files, setFiles] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [pathInput, setPathInput] = useState('');

  useEffect(() => {
    if (user?.teamId) {
      fetchFiles();
    }
  }, [user]);

  const fetchFiles = async () => {
    try {
      const response = await fileService.getTeamFiles(user.teamId);
      if (response.success) {
        setFiles(response.data);
      }
    } catch (error) {
      console.error('파일 목록 조회 실패:', error);
    }
  };

  const handleFileSelect = (e) => {
    setSelectedFile(e.target.files[0]);
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      alert('파일을 선택하세요');
      return;
    }

    try {
      const response = await fileService.uploadFile(user.teamId, selectedFile);
      if (response.success) {
        alert('파일이 업로드되었습니다');
        setSelectedFile(null);
        document.getElementById('file-input').value = '';
        fetchFiles();
      }
    } catch (error) {
      console.error('파일 업로드 실패:', error);
      alert(error.response?.data?.message || '파일 업로드에 실패했습니다');
    }
  };

  const handleDownload = async (fileId, fileName) => {
    try {
      let path = null;
      
      if (!isSecure && pathInput) {
        path = pathInput;
      }

      const response = await fileService.downloadFile(fileId, path);
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', fileName);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      console.error('파일 다운로드 실패:', error);
      alert(error.response?.data?.message || '파일 다운로드에 실패했습니다');
    }
  };

  const handleDelete = async (fileId) => {
    if (!window.confirm('파일을 삭제하시겠습니까?')) return;

    try {
      const response = await fileService.deleteFile(fileId);
      if (response.success) {
        alert('파일이 삭제되었습니다');
        fetchFiles();
      }
    } catch (error) {
      console.error('파일 삭제 실패:', error);
      alert(error.response?.data?.message || '파일 삭제에 실패했습니다');
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  if (!user?.teamId) {
    return (
      <Container maxWidth="lg" sx={{ mt: 4 }}>
        <Typography>팀에 소속되어 있지 않습니다</Typography>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" gutterBottom>
        팀 자료실
      </Typography>

      {!isSecure && (
        <Box sx={{ mb: 2, p: 2, bgcolor: 'error.light', borderRadius: 1 }}>
          <Typography variant="body2" color="error.contrastText">
            ⚠️ 취약 모드: 모든 파일 확장자 업로드 가능, 경로 조작 가능
          </Typography>
        </Box>
      )}

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          파일 업로드
        </Typography>
        
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
          <Input
            id="file-input"
            type="file"
            onChange={handleFileSelect}
          />
          <Button
            variant="contained"
            startIcon={<Upload />}
            onClick={handleUpload}
            disabled={!selectedFile}
          >
            업로드
          </Button>
        </Box>

        {!isSecure && (
          <Box sx={{ mt: 2, p: 2, bgcolor: 'warning.light', borderRadius: 1 }}>
            <Typography variant="caption" display="block" gutterBottom>
              경로 조작 테스트 (취약 모드)
            </Typography>
            <TextField
              fullWidth
              size="small"
              placeholder="예: ../../etc/passwd"
              value={pathInput}
              onChange={(e) => setPathInput(e.target.value)}
              helperText="다운로드 시 사용할 경로 입력"
            />
          </Box>
        )}
      </Paper>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>파일명</TableCell>
              <TableCell align="center">크기</TableCell>
              <TableCell align="center">업로드자</TableCell>
              <TableCell align="center">다운로드 횟수</TableCell>
              <TableCell align="center">작업</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {files.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} align="center">
                  업로드된 파일이 없습니다
                </TableCell>
              </TableRow>
            ) : (
              files.map((file) => (
                <TableRow key={file.id}>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <Folder sx={{ mr: 1 }} />
                      {file.originalName}
                    </Box>
                  </TableCell>
                  <TableCell align="center">{formatFileSize(file.fileSize)}</TableCell>
                  <TableCell align="center">-</TableCell>
                  <TableCell align="center">-</TableCell>
                  <TableCell align="center">
                    <IconButton
                      color="primary"
                      onClick={() => handleDownload(file.id, file.originalName)}
                    >
                      <Download />
                    </IconButton>
                    <IconButton
                      color="error"
                      onClick={() => handleDelete(file.id)}
                    >
                      <Delete />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Container>
  );
};

export default FilePage;