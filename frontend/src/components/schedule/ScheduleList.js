"use client"

import { useState, useEffect } from "react"
import {
  Container,
  Typography,
  Button,
  Box,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  IconButton,
  ToggleButton,
  ToggleButtonGroup,
} from "@mui/material"
import { Add, ChevronLeft, ChevronRight, CalendarViewWeek, CalendarMonth } from "@mui/icons-material"
import { useAuth } from "../../contexts/AuthContext"
import scheduleService from "../../services/scheduleService"

const ScheduleList = () => {
  const { user } = useAuth()
  const [schedules, setSchedules] = useState([])
  const [dialogOpen, setDialogOpen] = useState(false)
  const [currentDate, setCurrentDate] = useState(new Date())
  const [detailDialogOpen, setDetailDialogOpen] = useState(false)
  const [selectedSchedule, setSelectedSchedule] = useState(null)
  const [viewMode, setViewMode] = useState("week")
  const [formData, setFormData] = useState({
    title: "",
    content: "",
    startDate: "",
    endDate: "",
    teamId: "", // New field for teamId in form data
  })

  useEffect(() => {
    console.log("[v0] ScheduleList mounted, user:", user)
    if (user?.role === "ADMIN" || user?.teamId) {
      fetchSchedules()
    }
  }, [user])

  const fetchSchedules = async () => {
    try {
      console.log("[v0] Fetching schedules, user role:", user.role)
      
      let response;
      if (user.role === "ADMIN") {
        // 관리자는 무조건 getAllSchedules 호출
        response = await scheduleService.getAllSchedules()
      } else if (user.teamId) {
        // 일반 사용자는 자신의 팀 일정만
        response = await scheduleService.getTeamSchedules(user.teamId)
      } else {
        console.log("[v0] User has no team and is not admin")
        return
      }

      console.log("[v0] Schedule API response:", response)
      if (response.success) {
        console.log("[v0] Schedules data:", response.data)
        setSchedules(response.data) // 데이터 변환이 필요없다면 그대로 사용
      }
    } catch (error) {
      console.error("[v0] 일정 조회 실패:", error)
    }
  }

  const handleSubmit = async () => {
    if (!formData.title || !formData.startDate || !formData.endDate) {
      alert("모든 필드를 입력해주세요")
      return
    }

    try {
      const teamIdToUse = user.role === "ADMIN" && formData.teamId ? formData.teamId : user.teamId

      const response = await scheduleService.createSchedule(teamIdToUse, {
        ...formData,
        startDate: new Date(formData.startDate).toISOString(),
        endDate: new Date(formData.endDate).toISOString(),
      })

      if (response.success) {
        alert("일정이 등록되었습니다")
        setDialogOpen(false)
        setFormData({
          title: "",
          content: "",
          startDate: "",
          endDate: "",
          teamId: "", // Reset teamId in form data after submission
        })
        fetchSchedules()
      }
    } catch (error) {
      console.error("일정 등록 실패:", error)
      alert(error.response?.data?.message || "일정 등록에 실패했습니다")
    }
  }

  const handleDelete = async (scheduleId) => {
    if (!window.confirm("일정을 삭제하시겠습니까?")) return

    try {
      // teamId 파라미터 제거 또는 selectedSchedule의 teamId 사용
      const response = await scheduleService.deleteSchedule(
        selectedSchedule.teamId || user.teamId, 
        scheduleId
      )
      if (response.success) {
        alert("일정이 삭제되었습니다")
        setDetailDialogOpen(false)
        fetchSchedules()
      }
    } catch (error) {
      console.error("일정 삭제 실패:", error)
      alert(error.response?.data?.message || "일정 삭제에 실패했습니다")
    }
  }

  const getWeekStart = (date) => {
    const d = new Date(date)
    const day = d.getDay()
    const diff = d.getDate() - day
    return new Date(d.setDate(diff))
  }

  const getWeekDays = (startDate) => {
    const days = []
    for (let i = 0; i < 7; i++) {
      const date = new Date(startDate)
      date.setDate(startDate.getDate() + i)
      days.push(date)
    }
    return days
  }

  const getSchedulesForDate = (date) => {
    return schedules.filter((schedule) => {
      const scheduleStart = new Date(schedule.startDate)
      const scheduleEnd = new Date(schedule.endDate)
      const targetDate = new Date(date)

      targetDate.setHours(0, 0, 0, 0)
      scheduleStart.setHours(0, 0, 0, 0)
      scheduleEnd.setHours(0, 0, 0, 0)

      return targetDate >= scheduleStart && targetDate <= scheduleEnd
    })
  }

  const handleScheduleClick = (schedule) => {
    setSelectedSchedule(schedule)
    setDetailDialogOpen(true)
  }

  const getSpanningSchedules = (weekDays) => {
    const spanningSchedules = []

    schedules.forEach((schedule) => {
      const scheduleStart = new Date(schedule.startDate)
      const scheduleEnd = new Date(schedule.endDate)
      scheduleStart.setHours(0, 0, 0, 0)
      scheduleEnd.setHours(0, 0, 0, 0)

      const weekStart = new Date(weekDays[0])
      const weekEnd = new Date(weekDays[6])
      weekStart.setHours(0, 0, 0, 0)
      weekEnd.setHours(0, 0, 0, 0)

      if (scheduleEnd >= weekStart && scheduleStart <= weekEnd) {
        const visibleStart = scheduleStart > weekStart ? scheduleStart : weekStart
        const visibleEnd = scheduleEnd < weekEnd ? scheduleEnd : weekEnd

        const startIndex = weekDays.findIndex((day) => {
          const d = new Date(day)
          d.setHours(0, 0, 0, 0)
          return d.getTime() === visibleStart.getTime()
        })

        const endIndex = weekDays.findIndex((day) => {
          const d = new Date(day)
          d.setHours(0, 0, 0, 0)
          return d.getTime() === visibleEnd.getTime()
        })

        if (startIndex !== -1 && endIndex !== -1) {
          spanningSchedules.push({
            ...schedule,
            startIndex: startIndex >= 0 ? startIndex : 0,
            spanLength: endIndex - startIndex + 1,
          })
        }
      }
    })

    return spanningSchedules
  }

  const renderWeeklyCalendar = () => {
    const weekStart = getWeekStart(currentDate)
    const weekDays = getWeekDays(weekStart)
    const weekDayNames = ["일", "월", "화", "수", "목", "금", "토"]
    const today = new Date()
    today.setHours(0, 0, 0, 0)
    const spanningSchedules = getSpanningSchedules(weekDays)

    return (
      <Box sx={{ mt: 3 }}>
        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: "repeat(7, 1fr)",
            gap: 2,
            mb: 2,
          }}
        >
          {weekDays.map((date, index) => {
            const isToday = date.getTime() === today.getTime()
            const dayOfWeek = date.getDay()

            return (
              <Box
                key={index}
                sx={{
                  textAlign: "center",
                  pb: 1.5,
                  borderBottom: "2px solid rgba(55, 53, 47, 0.09)",
                }}
              >
                <Typography
                  sx={{
                    fontSize: "0.875rem",
                    fontWeight: 600,
                    color: dayOfWeek === 0 ? "#dc2626" : dayOfWeek === 6 ? "#0284c7" : "#6b7280",
                    mb: 0.5,
                  }}
                >
                  {weekDayNames[dayOfWeek]}
                </Typography>
                <Typography
                  sx={{
                    fontSize: "1.5rem",
                    fontWeight: isToday ? 700 : 600,
                    color: isToday ? "#37352f" : "#6b7280",
                  }}
                >
                  {date.getDate()}
                </Typography>
              </Box>
            )
          })}
        </Box>

        <Box sx={{ position: "relative", minHeight: "400px" }}>
          {spanningSchedules.map((schedule, idx) => {
            const colors = [
              { bg: "#f0f9ff", border: "#0284c7", text: "#0369a1", hover: "#e0f2fe" },
              { bg: "#fef3c7", border: "#f59e0b", text: "#d97706", hover: "#fde68a" },
              { bg: "#f0fdf4", border: "#10b981", text: "#059669", hover: "#dcfce7" },
              { bg: "#fce7f3", border: "#ec4899", text: "#db2777", hover: "#fbcfe8" },
              { bg: "#ede9fe", border: "#8b5cf6", text: "#7c3aed", hover: "#ddd6fe" },
            ]
            const color = colors[idx % colors.length]

            return (
              <Box
                key={schedule.id}
                onClick={() => handleScheduleClick(schedule)}
                sx={{
                  position: "absolute",
                  top: `${idx * 70}px`,
                  left: `calc(${(schedule.startIndex / 7) * 100}% + ${schedule.startIndex * 8}px)`,
                  width: `calc(${(schedule.spanLength / 7) * 100}% - ${(7 - schedule.spanLength) * 8}px)`,
                  p: 2,
                  backgroundColor: color.bg,
                  borderLeft: `4px solid ${color.border}`,
                  borderRadius: 2,
                  cursor: "pointer",
                  transition: "all 0.2s",
                  boxShadow: "rgba(15, 15, 15, 0.05) 0px 1px 3px",
                  "&:hover": {
                    backgroundColor: color.hover,
                    boxShadow: "rgba(15, 15, 15, 0.1) 0px 3px 8px",
                    transform: "translateY(-1px)",
                  },
                }}
              >
                <Typography
                  sx={{
                    fontSize: "1rem",
                    fontWeight: 600,
                    color: color.text,
                    mb: 0.5,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                  dangerouslySetInnerHTML={{ __html: schedule.content }}
                />
                {/* dangerouslySetInnerHTML 삽입(제목XSS)   */}
                <Typography
                  sx={{
                    fontSize: "0.8125rem",
                    color: "#6b7280",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {new Date(schedule.startDate).getMonth() + 1}/{new Date(schedule.startDate).getDate()} -{" "}
                  {new Date(schedule.endDate).getMonth() + 1}/{new Date(schedule.endDate).getDate()}
                </Typography>
              </Box>
            )
          })}
        </Box>
      </Box>
    )
  }

  const renderMonthlyCalendar = () => {
    const year = currentDate.getFullYear()
    const month = currentDate.getMonth()
    const firstDay = new Date(year, month, 1)
    const lastDay = new Date(year, month + 1, 0)
    const startingDayOfWeek = firstDay.getDay()
    const daysInMonth = lastDay.getDate()

    const calendarDays = []
    for (let i = 0; i < startingDayOfWeek; i++) {
      calendarDays.push(null)
    }
    for (let i = 1; i <= daysInMonth; i++) {
      calendarDays.push(new Date(year, month, i))
    }

    const weekDayNames = ["일", "월", "화", "수", "목", "금", "토"]
    const today = new Date()
    today.setHours(0, 0, 0, 0)

    // Calculate continuous event blocks for monthly view
    const eventRows = []
    const processedSchedules = new Set()

    schedules.forEach((schedule) => {
      if (processedSchedules.has(schedule.id)) return

      const start = new Date(schedule.startDate)
      const end = new Date(schedule.endDate)
      start.setHours(0, 0, 0, 0)
      end.setHours(0, 0, 0, 0)

      // Only show events in current month
      if (end < firstDay || start > lastDay) return

      // Find which week row this event starts in
      const effectiveStart = start < firstDay ? firstDay : start
      const effectiveEnd = end > lastDay ? lastDay : end

      const startDayIndex = calendarDays.findIndex((d) => d && d.getTime() === effectiveStart.getTime())

      if (startDayIndex === -1) return

      const daysDiff = Math.floor((effectiveEnd - effectiveStart) / (1000 * 60 * 60 * 24)) + 1

      eventRows.push({
        schedule,
        startIndex: startDayIndex,
        duration: daysDiff,
      })

      processedSchedules.add(schedule.id)
    })

    return (
      <Box sx={{ mt: 3, position: "relative" }}>
        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: "repeat(7, 1fr)",
            gap: 1,
            mb: 1,
          }}
        >
          {weekDayNames.map((day, index) => (
            <Box
              key={index}
              sx={{
                textAlign: "center",
                p: 1.5,
                fontWeight: 600,
                fontSize: "0.9375rem",
                color: index === 0 ? "#dc2626" : index === 6 ? "#0284c7" : "#6b7280",
              }}
            >
              {day}
            </Box>
          ))}
        </Box>

        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: "repeat(7, 1fr)",
            gap: 1,
            position: "relative",
          }}
        >
          {calendarDays.map((date, index) => {
            if (!date) {
              return <Box key={index} sx={{ minHeight: "100px" }} />
            }

            const isToday = date.getTime() === today.getTime()
            const dayOfWeek = date.getDay()

            return (
              <Box
                key={index}
                sx={{
                  minHeight: "100px",
                  border: "1px solid rgba(55, 53, 47, 0.09)",
                  borderRadius: 1.5,
                  p: 1,
                  backgroundColor: isToday ? "rgba(55, 53, 47, 0.03)" : "#ffffff",
                  transition: "all 0.2s",
                  "&:hover": {
                    boxShadow: "rgba(15, 15, 15, 0.05) 0px 2px 6px",
                  },
                  position: "relative",
                }}
              >
                <Typography
                  sx={{
                    fontSize: "0.9375rem",
                    fontWeight: isToday ? 700 : 600,
                    color: dayOfWeek === 0 ? "#dc2626" : dayOfWeek === 6 ? "#0284c7" : isToday ? "#37352f" : "#6b7280",
                  }}
                >
                  {date.getDate()}
                </Typography>
              </Box>
            )
          })}

          {eventRows.map((eventRow, idx) => {
            const rowNumber = Math.floor(eventRow.startIndex / 7)
            const colStart = (eventRow.startIndex % 7) + 1
            const colEnd = Math.min(colStart + eventRow.duration, 8)
            const actualDuration = colEnd - colStart

            // If event spans multiple weeks, render multiple blocks
            const blocks = []
            let remainingDuration = eventRow.duration
            let currentColStart = colStart
            let currentRow = rowNumber

            while (remainingDuration > 0) {
              const daysInThisRow = Math.min(8 - currentColStart, remainingDuration)

              blocks.push(
                <Box
                  key={`${eventRow.schedule.id}-${currentRow}`}
                  onClick={() => handleScheduleClick(eventRow.schedule)}
                  sx={{
                    position: "absolute",
                    top: `calc(${currentRow * 108}px + 36px)`,
                    left: `calc((100% + 8px) / 7 * ${currentColStart - 1})`,
                    width: `calc((100% + 8px) / 7 * ${daysInThisRow} - 8px)`,
                    zIndex: 10,
                    p: 0.75,
                    backgroundColor: "#f0f9ff",
                    borderLeft: "3px solid #0284c7",
                    borderRadius: 0.75,
                    cursor: "pointer",
                    transition: "all 0.2s",
                    "&:hover": {
                      backgroundColor: "#e0f2fe",
                      transform: "translateY(-1px)",
                      boxShadow: "rgba(15, 15, 15, 0.1) 0px 2px 8px",
                    },
                  }}
                >
                  <Typography
                    sx={{
                      fontSize: "0.8125rem",
                      fontWeight: 600,
                      color: "#0369a1",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {eventRow.schedule.title}
                  </Typography>
                </Box>,
              )

              remainingDuration -= daysInThisRow
              currentColStart = 1
              currentRow++
            }

            return blocks
          })}
        </Box>
      </Box>
    )
  }

  if (!user?.teamId && user?.role !== "ADMIN") {
    return (
      <Container maxWidth="lg" sx={{ mt: 4 }}>
        <Typography>팀에 소속되어 있지 않습니다</Typography>
      </Container>
    )
  }

  const weekStart = getWeekStart(currentDate)
  const weekEnd = new Date(weekStart)
  weekEnd.setDate(weekStart.getDate() + 6)

  const handlePrev = () => {
    const newDate = new Date(currentDate)
    if (viewMode === "week") {
      newDate.setDate(newDate.getDate() - 7)
    } else {
      newDate.setMonth(newDate.getMonth() - 1)
    }
    setCurrentDate(newDate)
  }

  const handleNext = () => {
    const newDate = new Date(currentDate)
    if (viewMode === "week") {
      newDate.setDate(newDate.getDate() + 7)
    } else {
      newDate.setMonth(newDate.getMonth() + 1)
    }
    setCurrentDate(newDate)
  }

  const handleToday = () => {
    setCurrentDate(new Date())
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 2, mb: 4 }}>
      <Box sx={{ mb: 5 }}>
        <Typography variant="h4" sx={{ mb: 1, fontWeight: 700, fontSize: "2.5rem" }}>
          팀 일정
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ fontSize: "1.125rem" }}>
          {user.teamName} 팀의 일정을 확인하세요
        </Typography>
      </Box>

      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
          <IconButton
            onClick={handlePrev}
            sx={{
              border: "1px solid rgba(55, 53, 47, 0.09)",
              "&:hover": { bgcolor: "rgba(55, 53, 47, 0.03)" },
            }}
          >
            <ChevronLeft />
          </IconButton>
          <Typography
            variant="h5"
            sx={{ fontWeight: 600, fontSize: "1.25rem", minWidth: "280px", textAlign: "center" }}
          >
            {viewMode === "week"
              ? `${weekStart.getFullYear()}년 ${weekStart.getMonth() + 1}월 ${weekStart.getDate()}일 - ${weekEnd.getMonth() + 1}월 ${weekEnd.getDate()}일`
              : `${currentDate.getFullYear()}년 ${currentDate.getMonth() + 1}월`}
          </Typography>
          <IconButton
            onClick={handleNext}
            sx={{
              border: "1px solid rgba(55, 53, 47, 0.09)",
              "&:hover": { bgcolor: "rgba(55, 53, 47, 0.03)" },
            }}
          >
            <ChevronRight />
          </IconButton>
          <Button
            variant="outlined"
            size="small"
            onClick={handleToday}
            sx={{
              borderColor: "rgba(55, 53, 47, 0.16)",
              color: "#37352f",
              fontSize: "0.9375rem",
              "&:hover": {
                borderColor: "#37352f",
                bgcolor: "rgba(55, 53, 47, 0.03)",
              },
            }}
          >
            오늘
          </Button>
        </Box>

        <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
          <ToggleButtonGroup
            value={viewMode}
            exclusive
            onChange={(e, newMode) => {
              if (newMode !== null) {
                setViewMode(newMode)
              }
            }}
            size="small"
          >
            <ToggleButton
              value="week"
              sx={{
                px: 2,
                fontSize: "0.9375rem",
                "&.Mui-selected": {
                  bgcolor: "#37352f",
                  color: "#ffffff",
                  "&:hover": { bgcolor: "#2c2a27" },
                },
              }}
            >
              <CalendarViewWeek sx={{ mr: 0.5, fontSize: "1.125rem" }} />
              주간
            </ToggleButton>
            <ToggleButton
              value="month"
              sx={{
                px: 2,
                fontSize: "0.9375rem",
                "&.Mui-selected": {
                  bgcolor: "#37352f",
                  color: "#ffffff",
                  "&:hover": { bgcolor: "#2c2a27" },
                },
              }}
            >
              <CalendarMonth sx={{ mr: 0.5, fontSize: "1.125rem" }} />
              월간
            </ToggleButton>
          </ToggleButtonGroup>

          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() => setDialogOpen(true)}
            sx={{
              bgcolor: "#37352f",
              color: "#ffffff",
              fontSize: "1rem",
              "&:hover": { bgcolor: "#2c2a27" },
            }}
          >
            일정 추가
          </Button>
        </Box>
      </Box>

      {viewMode === "week" ? renderWeeklyCalendar() : renderMonthlyCalendar()}

      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ fontSize: "1.5rem", fontWeight: 600 }}>일정 추가</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth
            label="제목"
            value={formData.title}
            onChange={(e) => setFormData({ ...formData, title: e.target.value })}
            sx={{ mt: 2, mb: 2 }}
            required
          />
          <TextField
            fullWidth
            label="내용"
            multiline
            rows={3}
            value={formData.content}
            onChange={(e) => setFormData({ ...formData, content: e.target.value })}
            sx={{ mb: 2 }}
          />
          <TextField
            fullWidth
            label="시작 날짜"
            type="datetime-local"
            value={formData.startDate}
            onChange={(e) => setFormData({ ...formData, startDate: e.target.value })}
            InputLabelProps={{ shrink: true }}
            sx={{ mb: 2 }}
            required
          />
          <TextField
            fullWidth
            label="종료 날짜"
            type="datetime-local"
            value={formData.endDate}
            onChange={(e) => setFormData({ ...formData, endDate: e.target.value })}
            InputLabelProps={{ shrink: true }}
            required
          />
          {user.role === "ADMIN" && (
            <TextField
              fullWidth
              label="팀 ID"
              value={formData.teamId}
              onChange={(e) => setFormData({ ...formData, teamId: e.target.value })}
              sx={{ mt: 2 }}
              required
            />
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2.5 }}>
          <Button onClick={() => setDialogOpen(false)} sx={{ fontSize: "1rem" }}>
            취소
          </Button>
          <Button
            onClick={handleSubmit}
            variant="contained"
            sx={{
              fontSize: "1rem",
              bgcolor: "#37352f",
              color: "#ffffff",
              "&:hover": { bgcolor: "#2c2a27" },
            }}
          >
            등록
          </Button>
        </DialogActions>
      </Dialog>

      {selectedSchedule && (
        <Dialog open={detailDialogOpen} onClose={() => setDetailDialogOpen(false)} maxWidth="sm" fullWidth>
          <DialogTitle sx={{ fontSize: "1.5rem", fontWeight: 600 }}>일정 상세</DialogTitle>
          <DialogContent>
            <Box sx={{ mt: 2 }}>
              <Typography variant="h6" sx={{ mb: 2, fontWeight: 600, fontSize: "1.25rem" }}>
                {selectedSchedule.title}
              </Typography>

              <Box sx={{ mb: 2 }}>
                <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.875rem", mb: 0.5 }}>
                  시작
                </Typography>
                <Typography variant="body1" sx={{ fontSize: "1rem", mb: 1.5 }}>
                  {new Date(selectedSchedule.startDate).toLocaleString("ko-KR")}
                </Typography>

                <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.875rem", mb: 0.5 }}>
                  종료
                </Typography>
                <Typography variant="body1" sx={{ fontSize: "1rem", mb: 2 }}>
                  {new Date(selectedSchedule.endDate).toLocaleString("ko-KR")}
                </Typography>
              </Box>

              {selectedSchedule.content && (
                <Box sx={{ p: 2, bgcolor: "rgba(55, 53, 47, 0.03)", borderRadius: 1 }}>
                  <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.875rem", mb: 1 }}>
                    상세 내용
                  </Typography>
                  <Typography variant="body1" sx={{ fontSize: "1rem", lineHeight: 1.7, whiteSpace: "pre-wrap" }}>
                    {selectedSchedule.content}
                  </Typography>
                </Box>
              )}
            </Box>
          </DialogContent>
          <DialogActions sx={{ p: 2.5 }}>
            <Button onClick={() => handleDelete(selectedSchedule.id)} color="error" sx={{ fontSize: "1rem" }}>
              삭제
            </Button>
            <Button onClick={() => setDetailDialogOpen(false)} sx={{ fontSize: "1rem" }}>
              닫기
            </Button>
          </DialogActions>
        </Dialog>
      )}
    </Container>
  )
}

export default ScheduleList
