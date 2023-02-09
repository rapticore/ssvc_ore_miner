import sys
import logging

from rapticoressvc import helpers
from rapticoressvc.ssvc_ore import ssvc_recommendations


def start_script(asset, vul_details, public_status, environment, asset_type, asset_criticality):
    engine_check = helpers.initialize()
    if not engine_check:
        logging.error('DB engine could not be Initialized')
        sys.exit(1)
    result = ssvc_recommendations(asset, vul_details, public_status, environment, asset_type, asset_criticality)
    return result