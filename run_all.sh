#!/bin/bash

# 스크립트 종료 시(Ctrl+C) 백그라운드 프로세스들도 함께 종료
trap "kill 0" EXIT

# 포트 정리 함수
kill_port() {
  PORT=$1
  PID=$(lsof -ti :$PORT)
  if [ -n "$PID" ]; then
    echo "[Cleanup] Killing process $PID on port $PORT"
    kill -9 $PID
  fi
}

echo "=================================================="
echo "Cleaning up ports (8080, 3000, 3001, 5003)..."
echo "=================================================="
kill_port 8080 # Backend
kill_port 3000 # Frontend (Default)
kill_port 3001 # Frontend (Alternative)
kill_port 5003 # Scanner

echo "=================================================="
echo "Starting Mini_PJT2 Services..."
echo "=================================================="

# 1. Backend 실행
echo "[Backend] Starting Spring Boot..."
cd backend
./mvnw spring-boot:run &
cd ..

# 2. Frontend 실행
echo "[Frontend] Starting React..."
cd frontend
# 기존에 interactive 모드로 물어보는 것을 방지하기 위해 BROWSER=none 등 설정 가능하나,
# 포트를 이미 비웠으므로 npm start가 3000번을 잡을 것임.
npm start &
cd ..

# 3. Scanner 실행
echo "[Scanner] Starting Python Scanner (Port 5003)..."
export PORT=5003
python Scanner/app.py &

echo "=================================================="
echo "All services are running."
echo "Press Ctrl+C to stop all services."
echo "=================================================="

# 모든 백그라운드 프로세스가 종료될 때까지 대기
wait
