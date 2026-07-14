import time
import logging
import re
from urllib.parse import quote
from zapv2 import ZAPv2
from .models import ZAPAlert

log = logging.getLogger(__name__)

class ZAPClient:
    def __init__(self, host: str, port: int, api_key: str):
        self.zap = ZAPv2(
            apikey=api_key,
            proxies={"http": f"http://{host}:{port}", "https": f"http://{host}:{port}"}
        )
        self.context_id = None
        self.user_id = None

    def wait_for_zap(self, timeout: int = 60) -> None:
        log.info("Ожидание запуска ZAP...")
        for _ in range(timeout):
            try:
                if self.zap.core.version:
                    log.info(f"ZAP готов. Версия: {self.zap.core.version}")
                    return
            except Exception:
                pass
            time.sleep(1)
        raise RuntimeError("ZAP не ответил за отведенное время")

    def start_new_session(self) -> None:
        log.info("Создание новой сессии ZAP")
        self.zap.core.new_session()

    def setup_authentication(self, target_url: str, auth_config) -> None:
        if not auth_config.enabled:
            return

        log.info(f"Настройка аутентификации для {target_url}")
        context_name = "AuthContext"
        self.context_id = self.zap.context.new_context(context_name)
        
        # Включаем весь домен в контекст
        domain = re.search(r'https?://[^/]+', target_url).group(0)
        self.zap.context.include_in_context(context_name, f"{re.escape(domain)}.*")
        
        # Обязательно делаем контекст активным (In Scope)
        self.zap.context.set_context_in_scope(context_name, True)
        
        # Настраиваем Form-based Auth
        login_data = f"{auth_config.username_field}={auth_config.username}&{auth_config.password_field}={auth_config.password}"
        auth_method_params = f"loginUrl={auth_config.login_url}&loginRequestData={quote(login_data)}"
        
        self.zap.authentication.set_authentication_method(
            self.context_id, "form-based", auth_method_params
        )
        
        if auth_config.logged_in_indicator:
            self.zap.authentication.set_logged_in_indicator(
                self.context_id, auth_config.logged_in_indicator
            )
            
        self.user_id = self.zap.users.new_user(self.context_id, "AuthUser")
        creds = f"username={auth_config.username}&password={auth_config.password}"
        self.zap.users.set_authentication_credentials(self.context_id, self.user_id, creds)
        self.zap.users.set_user_enabled(self.context_id, self.user_id, "true")
        
        log.info(f"Аутентификация настроена. Context ID: {self.context_id}, User ID: {self.user_id}")

    def spider_url(self, url: str) -> None:
        log.info(f"Запуск Spider для {url}")
        if self.context_id and self.user_id:
            # ВАЖНО: Для spider порядок аргументов (context_id, user_id, url)
            scan_id = self.zap.spider.scan_as_user(self.context_id, self.user_id, url)
            log.info(f"Spider запущен от имени пользователя. Scan ID: {scan_id}")
        else:
            scan_id = self.zap.spider.scan(url)
        self._wait_for_traditional_scan(scan_id, "Spider")

    def active_scan_url(self, url: str) -> None:
        log.info(f"Запуск Active Scan для {url}")
        if self.context_id and self.user_id:
            # ВАЖНО: Для ascan порядок аргументов (url, context_id, user_id)
            scan_id = self.zap.ascan.scan_as_user(url, self.context_id, self.user_id)
            log.info(f"Active Scan запущен от имени пользователя. Scan ID: {scan_id}")
        else:
            scan_id = self.zap.ascan.scan(url)
        self._wait_for_traditional_scan(scan_id, "Active Scan")
        
    def get_alerts(self) -> list[ZAPAlert]:
        log.info("Сбор алертов из ZAP...")
        raw_alerts = self.zap.core.alerts()
        alerts = []
        
        for a in raw_alerts:
            alert_id = a.get('id')
            if not alert_id:
                continue
            try:
                full_details = self.zap.core.alert(alert_id)
                if isinstance(full_details, dict):
                    a['request_header'] = full_details.get('requestHeader')
                    a['response_header'] = full_details.get('responseHeader')
                    a['response_body'] = full_details.get('responseBody')
            except Exception as e:
                log.warning(f"Не удалось получить детали для алерта {alert_id}: {e}")
                
            alerts.append(ZAPAlert(**a))
            
        log.info(f"Собрано алертов: {len(alerts)}")
        return alerts

    def _wait_for_traditional_scan(self, scan_id: str, scan_name: str, poll_interval: int = 2) -> None:
        while True:
            try:
                status = int(self.zap.spider.status(scan_id)) if scan_name == "Spider" else int(self.zap.ascan.status(scan_id))
            except Exception:
                status = 0
            
            if status >= 100:
                log.info(f"{scan_name} завершен.")
                break
            
            log.info(f"{scan_name} прогресс: {status}%")
            time.sleep(poll_interval)