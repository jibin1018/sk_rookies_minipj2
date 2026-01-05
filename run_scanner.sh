#!/bin/bash

# 색상 정의
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Scanner(Next.js + Python CLI) 실행 스크립트 ===${NC}"

# Scanner 디렉토리로 이동
cd Scanner || exit

# 1. Python 환경 설정 (CLI 실행용)
echo -e "${YELLOW}[1/3] Python 환경 설정 중...${NC}"
if [ ! -d "venv" ]; then
    echo -e "가상환경 생성..."
    python3 -m venv venv
fi

source venv/bin/activate
pip install -q -r requirements.txt
echo -e "${GREEN}Python 의존성 설치 완료${NC}"

# 2. Node.js 환경 설정
echo -e "${YELLOW}[2/3] Node.js 패키지 설치 중...${NC}"
if [ ! -d "node_modules" ]; then
    npm install
else
    # 변경사항이 있을 수 있으므로 install은 하는게 좋음, 하지만 속도를 위해 생략 가능하나 안전하게 실행
    echo "node_modules 확인됨."
fi

# 3. Next.js 실행
echo -e "${YELLOW}[3/3] Next.js 앱 실행 중...${NC}"
echo -e "${GREEN}http://localhost:3000 에서 접속 가능합니다.${NC}"

# Python 가상환경 내에서 Next.js를 실행하면, 
# spawn('python3') 호출 시 venv의 python이 사용되길 기대하지만,
# spawn은 기본적으로 PATH를 따름.
# npm run dev 스크립트가 실행되는 쉘의 PATH에 venv/bin이 포함되어 있어야 함.
# source venv/bin/activate 했으므로 현재 쉘에서는 적용됨.

npm run dev
