from parser_service.models import AIAnalysisResult


def test_ai_response_normalizes_markdown_fenced_json_and_weird_values() -> None:
    payload = {
        "result": """```json
        {
          "score": "91%",
          "severity": "CRIT",
          "category": "HTTP",
          "explanation": "Repeated suspicious requests detected.",
          "recommended_action": " Review access permissions "
        }
        ```"""
    }

    result = AIAnalysisResult.from_ai_payload(payload)

    assert result.score == 0.91
    assert result.severity.value == "critical"
    assert result.category == "web"
    assert result.recommended_action == "review_access"


def test_ai_response_clamps_and_defaults_unexpected_values() -> None:
    result = AIAnalysisResult.from_ai_payload(
        {
            "analysis": {
                "score": "120",
                "severity": "warning",
                "category": "mystery",
                "recommended_action": "please inspect immediately",
            }
        }
    )

    assert result.score == 1.0
    assert result.severity.value == "medium"
    assert result.category == "general"
    assert result.recommended_action == "investigate"
