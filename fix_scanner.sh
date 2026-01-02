#!/bin/bash

# 색상 정의
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== Scanner 환경 복구 스크립트 ===${NC}"

# Scanner 디렉토리로 이동
cd Scanner || exit 1

# 1. 기존 venv 완전 삭제
echo -e "${YELLOW}[1/6] 손상된 가상환경 삭제 중...${NC}"
if [ -d "venv" ]; then
    rm -rf venv
    echo -e "${GREEN}가상환경 삭제 완료${NC}"
else
    echo -e "${YELLOW}기존 가상환경 없음${NC}"
fi

# 2. Python 버전 확인
echo -e "${YELLOW}[2/6] Python 버전 확인...${NC}"
if command -v python3.12 &> /dev/null; then
    PYTHON_CMD="python3.12"
    echo -e "${GREEN}Python 3.12 사용${NC}"
elif command -v python3.11 &> /dev/null; then
    PYTHON_CMD="python3.11"
    echo -e "${GREEN}Python 3.11 사용${NC}"
elif command -v python3.10 &> /dev/null; then
    PYTHON_CMD="python3.10"
    echo -e "${GREEN}Python 3.10 사용${NC}"
else
    PYTHON_CMD="python3"
    echo -e "${YELLOW}Python 3 사용 (버전: $($PYTHON_CMD --version))${NC}"
    echo -e "${RED}경고: Python 3.14는 일부 패키지와 호환되지 않을 수 있습니다.${NC}"
fi

$PYTHON_CMD --version

# 3. 새 가상환경 생성
echo -e "${YELLOW}[3/6] 새 가상환경 생성 중...${NC}"
$PYTHON_CMD -m venv venv
echo -e "${GREEN}가상환경 생성 완료${NC}"

# 4. 가상환경 활성화
echo -e "${YELLOW}[4/6] 가상환경 활성화...${NC}"
source venv/bin/activate

# 5. pip 업그레이드
echo -e "${YELLOW}[5/6] pip 업그레이드...${NC}"
pip install --upgrade pip setuptools wheel

# 6. 의존성 설치
echo -e "${YELLOW}[6/6] 의존성 설치 중...${NC}"
pip install --force-reinstall -r requirements.txt

echo ""
echo -e "${GREEN}=== 복구 완료 ===${NC}"
echo -e "${YELLOW}이제 run_scanner_improved.sh를 실행하세요:${NC}"
echo -e "${GREEN}./run_scanner_improved.sh${NC}"
echo ""
