#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XXE (XML External Entity) 취약점 탐지
"""

import re
from pathlib import Path

XXE_PATTERNS = {
    'python': [
        (r'etree\.parse\s*\(', 'lxml.etree.parse (XXE 위험)'),
        (r'etree\.fromstring\s*\(', 'lxml.etree.fromstring (XXE 위험)'),
        (r'xml\.etree\.ElementTree\.parse\s*\(', 'ElementTree.parse'),
        (r'xml\.dom\.minidom\.parse\s*\(', 'minidom.parse'),
    ],
    'java': [
        (r'DocumentBuilderFactory', 'DocumentBuilderFactory'),
        (r'SAXParserFactory', 'SAXParserFactory'),
        (r'XMLInputFactory', 'XMLInputFactory'),
        (r'TransformerFactory', 'TransformerFactory'),
    ],
    'php': [
        (r'simplexml_load_string\s*\(', 'simplexml_load_string'),
        (r'simplexml_load_file\s*\(', 'simplexml_load_file'),
        (r'DOMDocument.*?load', 'DOMDocument load'),
    ],
    'javascript': [
        (r'DOMParser\s*\(\s*\)', 'DOMParser (브라우저)'),
        (r'libxmljs', 'libxmljs (Node.js)'),
    ],
}

# 안전한 XXE 방지 패턴
SAFE_XXE_PATTERNS = [
    r'resolve_entities\s*=\s*False',
    r'setFeature.*?FEATURE_SECURE_PROCESSING.*?true',
    r'setFeature.*?disallow-doctype-decl.*?true',
    r'defusedxml',
]

def has_xxe_protection(content, line_num, context_lines=10):
    """XXE 방어 설정 확인"""
    lines = content.split('\n')
    start = max(0, line_num - 5)
    end = min(len(lines), line_num + context_lines)
    context = '\n'.join(lines[start:end])
    
    for pattern in SAFE_XXE_PATTERNS:
        if re.search(pattern, context, re.IGNORECASE):
            return True
    
    return False

def get_language(file_path):
    ext = file_path.suffix.lower()
    if ext == '.py': return 'python'
    elif ext in ['.js', '.ts']: return 'javascript'
    elif ext == '.java': return 'java'
    elif ext == '.php': return 'php'
    return None

def scan(project_path, target_files):
    """XXE 취약점 진단"""
    findings = []
    
    for file_path in target_files:
        language = get_language(file_path)
        if not language or language not in XXE_PATTERNS:
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//', '/*', '*')):
                    continue
                
                for pattern, description in XXE_PATTERNS[language]:
                    if re.search(pattern, line, re.IGNORECASE):
                        # XXE 방어 확인
                        if has_xxe_protection(content, line_num):
                            continue
                        
                        try:
                            rel_path = file_path.relative_to(project_path)
                        except:
                            rel_path = file_path
                        
                        findings.append({
                            'file': str(rel_path),
                            'line': line_num,
                            'type': f'{description} - XXE 방어 누락',
                            'snippet': line.strip()[:100]
                        })
                        break
        except:
            continue
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 XXE 취약점 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **외부 엔티티 비활성화**
```python
   # Python - lxml
   from lxml import etree
   parser = etree.XMLParser(resolve_entities=False)
   tree = etree.parse(source, parser)
   
   # Python - defusedxml 사용 (권장)
   import defusedxml.ElementTree as ET
   tree = ET.parse(source)
   
   # Java
   DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
   dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
   dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
   dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
   
   # PHP
   libxml_disable_entity_loader(true);
```

2. **DTD 처리 비활성화**

3. **JSON 사용 고려**
   - XML 대신 JSON 사용

4. **입력 검증**
   - DOCTYPE 선언 거부
            '''
        }
    
    return {'status': 'SAFE', 'details': 'XXE 취약점 없음'}