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
} from '@mui/material';
import { Upload, Download, Delete, Folder } from '@mui/icons-material';
import { useAuth } from '../../contexts/AuthContext';
import fileService from '../../services/fileService';

const FilePage = () => {
  const { user } = useAuth();
  const [files, setFiles] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);

  useEffect(() => {
    if (user?.teamId) fetchFiles();
  }, [user]);

  const fetchFiles = async () => {
    try {
      const res = await fileService.getTeamFiles(user.teamId);
      if (res.success) setFiles(res.data);
    } catch (e) {
      console.error(e);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) return alert("파일 선택");
    try {
      const res = await fileService.uploadFile(user.teamId, selectedFile);
      if (res.success) {
        alert("업로드 완료");
        setSelectedFile(null);
        document.getElementById("file-input").value = "";
        fetchFiles();
      }
    } catch (e) {
      alert("업로드 실패");
    }
  };

  const handleDownload = async (id, name) => {
    const res = await fileService.downloadFile(id);
    const url = window.URL.createObjectURL(new Blob([res.data]));
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
  };

  const handleDelete = async (id) => {
    if (!window.confirm("삭제?")) return;
    const res = await fileService.deleteFile(id);
    if (res.success) fetchFiles();
  };

  return (
    <Container maxWidth="lg" sx={{ mt: 4 }}>
      <Typography variant="h4" gutterBottom>팀 자료실</Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Input id="file-input" type="file" onChange={(e) => setSelectedFile(e.target.files[0])} />
        <Button startIcon={<Upload />} onClick={handleUpload}>업로드</Button>
      </Paper>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>파일명</TableCell>
              <TableCell align="center">작업</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {files.map((file) => (
              <TableRow key={file.id}>
                <TableCell>
                  <Folder sx={{ mr: 1 }} />
                  {file.originalName}
                </TableCell>
                <TableCell align="center">
                  <IconButton onClick={() => handleDownload(file.id, file.originalName)}>
                    <Download />
                  </IconButton>
                  <IconButton color="error" onClick={() => handleDelete(file.id)}>
                    <Delete />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Container>
  );
};

export default FilePage;
