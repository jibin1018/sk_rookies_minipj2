import React from 'react';
import {
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Toolbar,
} from '@mui/material';
import {
  Dashboard,
  Article,
  Schedule,
  AccessTime,
  Folder,
  Feedback,
  Restaurant,
  Description,
  People,
} from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';

const DRAWER_WIDTH = 240;

const menuItems = [
  { text: '대시보드', icon: <Dashboard />, path: '/dashboard' },
  { text: '사내 게시판', icon: <Article />, path: '/boards' },
  { text: '팀 일정', icon: <Schedule />, path: '/schedules' },
  { text: '근태 관리', icon: <AccessTime />, path: '/attendance' },
  { text: '팀 자료실', icon: <Folder />, path: '/files' },
  { text: '익명 건의함', icon: <Feedback />, path: '/suggestions' },
  { text: '구내식당', icon: <Restaurant />, path: '/cafeteria' },
  { text: '전자결재', icon: <Description />, path: '/approvals' },
  { text: '사원 관리', icon: <People />, path: '/employees' },
];

const Sidebar = () => {
  const navigate = useNavigate();
  const location = useLocation();

  return (
    <Drawer
      variant="permanent"
      sx={{
        width: DRAWER_WIDTH,
        flexShrink: 0,
        '& .MuiDrawer-paper': {
          width: DRAWER_WIDTH,
          boxSizing: 'border-box',
        },
      }}
    >
      <Toolbar />
      <List>
        {menuItems.map((item) => (
          <ListItem key={item.text} disablePadding>
            <ListItemButton
              selected={location.pathname === item.path}
              onClick={() => navigate(item.path)}
            >
              <ListItemIcon>{item.icon}</ListItemIcon>
              <ListItemText primary={item.text} />
            </ListItemButton>
          </ListItem>
        ))}
      </List>
    </Drawer>
  );
};

export default Sidebar;