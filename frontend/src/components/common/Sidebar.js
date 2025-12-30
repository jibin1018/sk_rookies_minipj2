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
import { useAuth } from "../../contexts/AuthContext"

const DRAWER_WIDTH = 240

const Sidebar = () => {
  const navigate = useNavigate()
  const location = useLocation()
  const { user } = useAuth()

  console.log("[v0] Sidebar - User:", user)
  console.log("[v0] Sidebar - User Role:", user?.role)

  const baseMenuItems = [
    { text: "대시보드", icon: <Dashboard />, path: "/dashboard" },
    { text: "사내 게시판", icon: <Article />, path: "/boards" },
    { text: "팀 일정", icon: <Schedule />, path: "/schedules" },
    { text: "근태 관리", icon: <AccessTime />, path: "/attendance" },
    { text: "팀 자료실", icon: <Folder />, path: "/files" },
    { text: "익명 건의함", icon: <Feedback />, path: "/suggestions" },
    { text: "구내식당", icon: <Restaurant />, path: "/cafeteria" },
    { text: "전자결재", icon: <Description />, path: "/approvals" },
  ]

  const adminMenuItem = { text: "사원 관리", icon: <People />, path: "/employees" }

  const menuItems = user?.role === "ADMIN" ? [...baseMenuItems, adminMenuItem] : baseMenuItems

  console.log("[v0] Sidebar - Menu Items:", menuItems)

  const handleNavigation = (path) => {
    console.log("[v0] Sidebar - Navigating to:", path)
    navigate(path)
  }

  return (
    <Drawer
      variant="permanent"
      sx={{
        width: DRAWER_WIDTH,
        flexShrink: 0,
        "& .MuiDrawer-paper": {
          width: DRAWER_WIDTH,
          boxSizing: "border-box",
          backgroundColor: "#fbfbfa",
          borderRight: "1px solid rgba(55, 53, 47, 0.09)",
          boxShadow: "none",
        },
      }}
    >
      <Toolbar sx={{ minHeight: "48px !important" }} />
      <Box sx={{ py: 3, px: 2 }}>
        <List sx={{ padding: 0 }}>
          {menuItems.map((item) => (
            <ListItem key={item.text} disablePadding sx={{ mb: 1 }}>
              <ListItemButton
                selected={location.pathname === item.path}
                onClick={() => handleNavigation(item.path)}
                sx={{
                  borderRadius: "6px",
                  py: 1.25,
                  px: 1.5,
                  minHeight: "36px",
                  transition: "all 0.15s ease",
                  "&.Mui-selected": {
                    backgroundColor: "rgba(46, 51, 56, 0.08)",
                    "& .MuiListItemIcon-root": {
                      color: "#37352f",
                    },
                    "& .MuiListItemText-primary": {
                      color: "#37352f",
                      fontWeight: 500,
                    },
                    "&:hover": {
                      backgroundColor: "rgba(46, 51, 56, 0.12)",
                    },
                  },
                  "&:hover": {
                    backgroundColor: "rgba(55, 53, 47, 0.08)",
                  },
                }}
              >
                <ListItemIcon
                  sx={{
                    minWidth: 36,
                    color: location.pathname === item.path ? "#37352f" : "#9b9a97",
                    transition: "color 0.15s ease",
                    "& svg": {
                      fontSize: "22px",
                    },
                  }}
                >
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={item.text}
                  primaryTypographyProps={{
                    fontSize: "0.9375rem",
                    fontWeight: location.pathname === item.path ? 500 : 400,
                    color: location.pathname === item.path ? "#37352f" : "#787774",
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
