import logging

def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Set to DEBUG to capture all levels of logs

    # File Handler for Errors
    file_handler = logging.FileHandler('errors.log')
    file_handler.setLevel(logging.ERROR)
    file_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)

# Setup logging for script
setup_logging()
logger = logging.getLogger(__name__)