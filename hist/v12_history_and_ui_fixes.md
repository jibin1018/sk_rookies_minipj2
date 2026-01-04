# Version 12: History 탭 및 UI 개선

## 날짜
2026-01-03

## 작업 내용

### 1. History 탭 보고서 필터링

**변경 파일**: `app.py`, `templates/index.html`

**문제점**:
- reports 폴더에 파일이 없는 스캔도 History에 표시됨

**해결**:
- `summarize_scan()` 함수에 `has_report` 필드 추가
- 보고서 파일 존재 여부 확인 후 플래그 설정
- index.html에서 `has_report === true`인 항목만 표시

### 2. 대상 IP 자동 추출

**변경 파일**: `app.py`

**이전**: "기존 점검 기록"으로 표시
**이후**: 보고서 파일에서 `**대상**: \`IP주소\`` 패턴 추출하여 실제 IP 표시

```python
match = re.search(r'\*\*대상\*\*:\s*`([^`]+)`', content)
if match:
    target_name = match.group(1)  # 예: 3.39.161.64
```

### 3. INFRA 보고서 로딩 수정

**변경 파일**: `app.py`

**문제점**: 
- `/api/report/raw/` API에서 `infra_scan_report_{id}.md` 패턴 누락

**해결**:
```python
possible_names = [
    f"scan_report_{scan_id}.md", 
    f"scan_report_{scan_id}.txt", 
    f"infra_scan_report_{scan_id}.md",  # 추가
    f"infra_scan_report_{scan_id}.txt"
]
```

### 4. 모달 상세 정보 가독성 개선

**변경 파일**: `templates/index.html`

**이전**: 
- `.report-viewer pre` 배경: `#1e293b` (어두운 색)
- 텍스트: `#e2e8f0` (밝은 색) → 드래그해야 보임

**이후**:
- 배경: `#f1f5f9` (밝은 회색)
- 텍스트: `#334155` (진한 회색) → 가독성 확보

### 5. 성능 카드 전체 스크립트 개수 표시

**변경 파일**: `templates/report.html`

**추가된 지표**:
- 전체 진단 스크립트: 82개
- 평균 응답시간
- 모듈별 스크립트 개수 합계

---

## 변경 파일 목록

| 파일 | 변경 내용 |
|------|----------|
| `app.py` | has_report, 대상 IP 추출, INFRA 보고서 패턴 |
| `templates/index.html` | pre 스타일, History 필터링 |
| `templates/report.html` | 전체 스크립트 개수 표시 |

---

## 스크립트 개수 현황 (v12 기준)

| 모듈 | 개수 |
|------|:----:|
| web | 54 |
| os | 7 |
| db | 6 |
| was | 4 |
| framework | 3 |
| network | 4 |
| cloud | 2 |
| web_server | 2 |
| **합계** | **82** |
