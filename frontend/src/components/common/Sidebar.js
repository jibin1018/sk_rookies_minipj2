"use client"
import { Drawer, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Toolbar, Box } from "@mui/material"
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
} from "@mui/icons-material"
import { useNavigate, useLocation } from "react-router-dom"

const DRAWER_WIDTH = 260

const menuItems = [
  { text: "대시보드", icon: <Dashboard />, path: "/dashboard" },
  { text: "사내 게시판", icon: <Article />, path: "/boards" },
  { text: "팀 일정", icon: <Schedule />, path: "/schedules" },
  { text: "근태 관리", icon: <AccessTime />, path: "/attendance" },
  { text: "팀 자료실", icon: <Folder />, path: "/files" },
  { text: "익명 건의함", icon: <Feedback />, path: "/suggestions" },
  { text: "구내식당", icon: <Restaurant />, path: "/cafeteria" },
  { text: "전자결재", icon: <Description />, path: "/approvals" },
  { text: "사원 관리", icon: <People />, path: "/employees" },
]

const Sidebar = () => {
  const navigate = useNavigate()
  const location = useLocation()

  return (
    <Drawer
      variant="permanent"
      sx={{
        width: DRAWER_WIDTH,
        flexShrink: 0,
        "& .MuiDrawer-paper": {
          width: DRAWER_WIDTH,
          boxSizing: "border-box",
          backgroundColor: "#ffffff",
          borderRight: "1px solid #e5e7eb",
          boxShadow: "0 1px 3px 0 rgba(0, 0, 0, 0.1)",
        },
      }}
    >
      <Toolbar />
      <Box sx={{ py: 2 }}>
        <List sx={{ px: 2 }}>
          {menuItems.map((item, index) => (
            <ListItem key={item.text} disablePadding sx={{ mb: 0.5 }}>
              <ListItemButton
                selected={location.pathname === item.path}
                onClick={() => navigate(item.path)}
                sx={{
                  borderRadius: "8px",
                  py: 1.25,
                  px: 2,
                  "&.Mui-selected": {
                    backgroundColor: "#eff6ff",
                    color: "#1e3a5f",
                    "& .MuiListItemIcon-root": {
                      color: "#1e3a5f",
                    },
                    "&:hover": {
                      backgroundColor: "#dbeafe",
                    },
                  },
                  "&:hover": {
                    backgroundColor: "#f9fafb",
                  },
                }}
              >
                <ListItemIcon
                  sx={{
                    minWidth: 40,
                    color: location.pathname === item.path ? "#1e3a5f" : "#6b7280",
                  }}
                >
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={item.text}
                  primaryTypographyProps={{
                    fontSize: "0.9375rem",
                    fontWeight: location.pathname === item.path ? 600 : 500,
                  }}
                />
              </ListItemButton>
            </ListItem>
          ))}
        </List>
      </Box>
    </Drawer>
  )
}

export default Sidebar
