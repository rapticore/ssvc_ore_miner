import logging
import os
from typing import Any, Dict

import urllib3
from aws_lambda_powertools.event_handler import api_gateway
from rapticoressvc import ssvc_recommendations
from urllib3.exceptions import InsecureRequestWarning

logger = logging.getLogger()

[logging.getLogger(p).setLevel(logging.ERROR) for p in ["boto3", "botocore"]]
urllib3.disable_warnings(InsecureRequestWarning)
disable_loggers = ["urllib3", "requests"]
for dl in disable_loggers:
    logging.getLogger(dl).setLevel("CRITICAL")

LOG_LEVEL = os.environ['LOG_LEVEL']
logger.setLevel(LOG_LEVEL)

app = api_gateway.ApiGatewayResolver(
    proxy_type=api_gateway.ProxyEventType.APIGatewayProxyEventV2
)


def lambda_handler(event: Dict[str, Any], context: object) -> Dict[str, Any]:
    return app.resolve(event, context)


@app.post("/ssvc_recommendation")
def get_ssvc_recommendation():
    """
    Returns SSVC Resolution advice
    """
    request_attributes = app.current_event.json_body
    asset = request_attributes.get("asset")
    vul_details = request_attributes.get("vul_details")
    public_status = request_attributes.get("public_status")
    environment = request_attributes.get("environment")
    asset_type = request_attributes.get("asset_type")
    asset_criticality = request_attributes.get("asset_criticality")
    return ssvc_recommendations(asset, vul_details, public_status, environment, asset_type, asset_criticality)
