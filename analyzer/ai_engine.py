"""
AI Analysis Engine
Uses Google Gemini API for intelligent code analysis, root-cause explanations, 
fix suggestions, and natural language interaction with the analysis results.
"""

import json
from typing import Optional, List


def get_ai_analysis(source_code: str, issues: list, api_key: str) -> dict:
    """Get AI-powered analysis of code issues using Google Gemini."""
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.0-flash')

        issues_text = ""
        for issue in issues[:15]:
            issues_text += f"\n- [{issue.severity.value}] {issue.title} (line {issue.line_number}): {issue.description}"

        prompt = f"""You are a senior software engineer performing a code review. Analyze the following Python code and the detected issues.

## Source Code:
```python
{source_code[:4000]}
```

## Detected Issues:
{issues_text if issues_text else "No automated issues detected."}

Provide a comprehensive analysis in the following JSON format (respond ONLY with valid JSON):
{{
    "overall_assessment": "A 2-3 sentence summary of the code quality",
    "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
    "top_concerns": [
        {{
            "title": "Concern title",
            "explanation": "Why this is a problem",
            "impact": "What could go wrong",
            "recommendation": "How to fix it"
        }}
    ],
    "root_cause_analysis": "Deep analysis of the most critical issues and their root causes",
    "improvement_priorities": [
        "Priority 1: ...",
        "Priority 2: ...",
        "Priority 3: ..."
    ],
    "positive_aspects": ["Things the code does well"],
    "security_notes": "Any security considerations",
    "test_recommendations": "What should be tested"
}}
"""
        response = model.generate_content(prompt)
        text = response.text.strip()

        # Clean up JSON response
        if text.startswith('```json'):
            text = text[7:]
        if text.startswith('```'):
            text = text[3:]
        if text.endswith('```'):
            text = text[:-3]
        text = text.strip()

        return json.loads(text)

    except ImportError:
        return {"error": "google-generativeai package not installed. Install with: pip install google-generativeai"}
    except Exception as e:
        return {"error": f"AI analysis failed: {str(e)}"}


def get_fix_suggestion(source_code: str, issue_title: str, issue_desc: str,
                       line_number: int, api_key: str) -> dict:
    """Get AI-powered fix suggestion for a specific issue."""
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.0-flash')

        prompt = f"""You are a senior software engineer. Fix the following issue in the Python code.

## Issue:
- **Title**: {issue_title}
- **Description**: {issue_desc}
- **Line**: {line_number}

## Source Code:
```python
{source_code[:4000]}
```

Provide the fix in the following JSON format (respond ONLY with valid JSON):
{{
    "explanation": "Why this fix works",
    "fixed_code": "The complete fixed version of the code",
    "changes_made": ["List of specific changes"],
    "before_snippet": "The problematic code snippet",
    "after_snippet": "The fixed code snippet",
    "verification": "How to verify the fix works"
}}
"""
        response = model.generate_content(prompt)
        text = response.text.strip()
        if text.startswith('```json'):
            text = text[7:]
        if text.startswith('```'):
            text = text[3:]
        if text.endswith('```'):
            text = text[:-3]
        text = text.strip()
        return json.loads(text)

    except Exception as e:
        return {"error": f"Fix suggestion failed: {str(e)}"}


def chat_with_code(source_code: str, issues: list, user_question: str, api_key: str) -> str:
    """Chat with AI about the code and its issues."""
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.0-flash')

        issues_text = ""
        for issue in issues[:10]:
            issues_text += f"\n- [{issue.severity.value}] {issue.title} (line {issue.line_number})"

        prompt = f"""You are a helpful senior software engineer assistant. The user is reviewing Python code and has a question about it.

## Code being analyzed:
```python
{source_code[:3000]}
```

## Known Issues:
{issues_text if issues_text else "No issues detected."}

## User's Question:
{user_question}

Provide a clear, helpful, and actionable answer. Use code examples where appropriate. Format your response in markdown.
"""
        response = model.generate_content(prompt)
        return response.text

    except Exception as e:
        return f"❌ Error: {str(e)}"
