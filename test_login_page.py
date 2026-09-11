from src.enrichment.content_signals import fetch_page_html, analyze_content

html = fetch_page_html("github.com/login")
result = analyze_content(html)
print(f"has_login_form: {result['has_login_form']}")
print(f"has_password_field: {result['has_password_field']}")
print(f"suspicious_phrases_found: {result['suspicious_phrases_found']}")
