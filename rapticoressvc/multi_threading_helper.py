import concurrent.futures
import logging
from concurrent.futures import as_completed

from tqdm import tqdm


def run_parallel(function, array, args: dict = None, max_workers=8, progress_description=None):
    return_values = []
    try:
        args = args or {}
        logging.debug(f"Scheduling parallel threads for {function.__name__}")
        progress_description = progress_description or f'Parallel threads progress for function {function.__name__}'
        with tqdm(total=len(array), desc=progress_description, unit='record') as progress_bar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(function, element, args) for element in array]
                for future in as_completed(futures):
                    progress_bar.update(1)
                    result = future.result()
                    result and return_values.append(result)
    except Exception as e:
        logging.exception(e)
    return return_values
