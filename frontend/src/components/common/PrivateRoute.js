"use client"
import { Navigate } from "react-router-dom"
import { useAuth } from "../../contexts/AuthContext"
import { CircularProgress, Box } from "@mui/material"

const PrivateRoute = ({ children, adminOnly = false }) => {
  const { isAuthenticated, loading, user } = useAuth()

  console.log(
    "[v0] PrivateRoute - isAuthenticated:",
    isAuthenticated,
    "loading:",
    loading,
    "user:",
    user,
    "adminOnly:",
    adminOnly,
  )

  if (loading) {
    return (
      <Box
        sx={{
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          height: "100vh",
        }}
      >
        <CircularProgress />
      </Box>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" />
  }

  if (adminOnly && user?.role !== "ADMIN") {
    console.log("[v0] Access denied - Admin only route, user role:", user?.role)
    return <Navigate to="/dashboard" />
  }

  return children
}

export default PrivateRoute
