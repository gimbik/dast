from pydantic import BaseModel, ConfigDict
from typing import Optional

class ZAPAlert(BaseModel):
    model_config = ConfigDict(extra="allow")
    
    id: str = ""
    pluginid: str = ""
    alert: str = ""
    name: str = ""
    riskcode: str = ""
    confidence: str = ""
    riskdesc: str = ""
    desc: str = ""
    solution: str = ""
    cweid: str = ""
    url: str = ""
    evidence: str = ""
    attack: str = ""
    
    # Обогащенные данные (ZAP отдаст их после запроса core.alert)
    request_header: Optional[str] = None
    response_header: Optional[str] = None
    response_body: Optional[str] = None