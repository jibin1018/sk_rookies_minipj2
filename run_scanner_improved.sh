#!/bin/bash

# 색상 정의
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Scanner 실행 스크립트 ===${NC}"

# 사용 가능한 포트 찾기 (5000 ~ 5002)
echo -e "${YELLOW}[1/5] 사용 가능한 포트 찾는 중...${NC}"
SCANNER_PORT=""
for port in 5000 5001 5002; do
    if ! lsof -ti:$port > /dev/null 2>&1; then
        SCANNER_PORT=$port
        echo -e "${GREEN}포트 $port 사용 가능${NC}"
        break
    else
        echo -e "${YELLOW}포트 $port 이미 사용 중${NC}"
    fi
done

if [ -z "$SCANNER_PORT" ]; then
    echo -e "${RED}사용 가능한 포트가 없습니다 (5000-5002 모두 사용 중)${NC}"
    echo -e "${YELLOW}기존 프로세스를 종료하시겠습니까? (y/n)${NC}"
    read -r response
    if [[ "$response" == "y" ]]; then
        kill -9 $(lsof -ti:5000) 2>/dev/null
        SCANNER_PORT=5000
        echo -e "${GREEN}포트 5000 확보 완료${NC}"
    else
        exit 1
    fi
fi

# Scanner 디렉토리로 이동
cd Scanner || {
    echo -e "${RED}Scanner 디렉토리를 찾을 수 없습니다.${NC}"
    exit 1
}

# Python 버전 확인
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Python3이 설치되어 있지 않습니다.${NC}"
    exit 1
fi

echo -e "${GREEN}[2/5] Python 버전 확인...${NC}"
python3 --version

# 가상환경 생성 및 활성화
if [ ! -d "venv" ]; then
    echo -e "${GREEN}[3/5] 가상환경 생성 중...${NC}"
    python3 -m venv venv
else
    echo -e "${YELLOW}[3/5] 기존 가상환경 사용${NC}"
fi

echo -e "${GREEN}가상환경 활성화...${NC}"
source venv/bin/activate

# 의존성 설치
echo -e "${GREEN}[4/5] 의존성 설치 중...${NC}"
pip install -q -r requirements.txt

# 임시 파일 및 캐시 정리 (venv 제외)
echo -e "${GREEN}[5/5] 캐시 정리 중...${NC}"
find . -path ./venv -prune -o -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find . -path ./venv -prune -o -type f -name "*.pyc" -delete 2>/dev/null
rm -rf temp/* 2>/dev/null

# 보고서 디렉토리 생성
mkdir -p reports
mkdir -p temp

echo ""
echo -e "${GREEN}=== Scanner 시작 ===${NC}"
echo -e "${YELLOW}웹 UI:       http://localhost:$SCANNER_PORT${NC}"
echo -e "${YELLOW}API 문서:    http://localhost:$SCANNER_PORT/api/docs${NC}"
echo -e "${YELLOW}헬스 체크:   http://localhost:$SCANNER_PORT/health${NC}"
echo -e "${YELLOW}웹 테스트:   31개 (기존 18개 + 신규 13개)${NC}"
echo ""
echo -e "${GREEN}종료하려면 Ctrl+C를 누르세요${NC}"
echo ""

# Flask 앱 실행 (개선된 방식)
export PORT=$SCANNER_PORT
python app.py
