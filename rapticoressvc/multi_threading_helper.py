import concurrent.futures
import logging
from concurrent.futures import as_completed


def run_parallel(function, array, args: dict = None, max_workers=8):
    return_values = []
    try:
        args = args or {}
        logging.debug(f"Scheduling parallel threads for {function.__name__}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(function, element, args) for element in array]
            for future in as_completed(futures):
                result = future.result()
                result and return_values.append(result)
    except Exception as e:
        logging.exception(e)
    return return_values
