import api from "./api"

const scheduleService = {
  getTeamSchedules: async (teamId) => {
    console.log("[v0] scheduleService.getTeamSchedules called with teamId:", teamId)
    const response = await api.get(`/teams/${teamId}/schedules`)
    console.log("[v0] scheduleService API raw response:", response)
    return response.data
  },

  // 관리자용 - 모든 일정 조회 (수정)
  getAllSchedules: async () => {
    console.log("[v0] scheduleService.getAllSchedules called (admin)")
    const response = await api.get(`/schedules/all`)  // /teams/0 제거
    console.log("[v0] scheduleService getAllSchedules API response:", response)
    return response.data
  },

  getSchedulesByDateRange: async (teamId, start, end) => {
    const response = await api.get(`/teams/${teamId}/schedules/range`, {
      params: { start, end },
    })
    return response.data
  },

  createSchedule: async (teamId, scheduleData) => {
    const response = await api.post(`/teams/${teamId}/schedules`, scheduleData)
    return response.data
  },

  deleteSchedule: async (teamId, scheduleId) => {
    const response = await api.delete(`/teams/${teamId}/schedules/${scheduleId}`)
    return response.data
  },
}

export default scheduleService