import sys
import json
import logging
from pathlib import Path
from src.llm_dast.config import load_config
from src.llm_dast.zap.client import ZAPClient
from src.llm_dast.llm.ollama_client import OllamaClient
from src.llm_dast.llm.prompt_renderer import PromptRenderer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

def main():
    config = load_config("config/default.yaml")
    
    zap = ZAPClient(host=config.zap.host, port=config.zap.port, api_key=config.zap.api_key)
    zap.wait_for_zap()
    zap.start_new_session()
    
    target = config.target["url"]
    
    # НОВОЕ: Настройка авторизации
    zap.setup_authentication(target, config.auth)
    
    if config.zap.scan.spider:
        zap.spider_url(target)
    if config.zap.scan.ajax_spider:
        zap.ajax_spider_url(target, max_duration=2)
    if config.zap.scan.active_scan:
        zap.active_scan_url(target)
        
    alerts = zap.get_alerts()
    print(f"\nВсего алертов найдено: {len(alerts)}")
    
    if not alerts:
        print("Алерт нет, тестировать LLM не на чем.")
        return

    from collections import Counter
    alert_counts = Counter([a.name for a in alerts])
    print("\n--- СВОДКА НАЙДЕННЫХ УЯЗВИМОСТЕЙ ---")
    for name, count in alert_counts.items():
        risk = next((a.riskdesc for a in alerts if a.name == name), "Unknown")
        print(f"[{count}] ({risk}) {name}")

    alerts_to_triage = alerts[:5]
    print(f"\n--- НАЧИНАЕМ ТРИАЖ ТОП-{len(alerts_to_triage)} АЛЕРТОВ ---")

    llm = OllamaClient(
        base_url=config.llm.base_url,
        model=config.llm.model,
        temperature=config.llm.temperature,
        json_mode=config.llm.json_mode
    )
    
    prompt_dir = Path("config/prompts")
    renderer = PromptRenderer(str(prompt_dir))
    system_prompt = (prompt_dir / "triage_system.txt").read_text()
    
    triaged_results = []

    for i, alert in enumerate(alerts_to_triage):
        print(f"\n[{i+1}/{len(alerts_to_triage)}] Анализирую: {alert.name} | URL: {alert.url[:60]}...")
        user_prompt = renderer.render("triage_user.txt", {"alert": alert})
        
        try:
            verdict = llm.chat(system_prompt, user_prompt)
            result = {
                "title": f"{alert.name} at {alert.url}",
                "severity": alert.riskdesc,
                "cwe": alert.cweid,
                "url": alert.url,
                "description": alert.desc,
                "mitigation": alert.solution,
                "llm_triage": {
                    "status": verdict.get("triage_status"),
                    "confidence": verdict.get("confidence"),
                    "justification": verdict.get("justification"),
                    "remediation_steps": verdict.get("remediation")
                },
                "raw_request": alert.request_header,
                "raw_response_header": alert.response_header
            }
            triaged_results.append(result)
            print(f"  -> Статус: {verdict.get('triage_status')} (Уверенность: {verdict.get('confidence')})")
        except Exception as e:
            print(f"  -> Ошибка LLM: {e}")

    report_path = "report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(triaged_results, f, indent=4, ensure_ascii=False)
        
    print(f"\n{'='*50}")
    print(f"✅ Триаж завершен. Отчет сохранен в файл: {report_path}")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()