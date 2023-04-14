import logging
from .nvd_data_helper import update_nvd_data

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


def lambda_handler(event, context):
    update_nvd_data()
