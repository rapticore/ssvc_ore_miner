import concurrent.futures
import logging


def run_parallel(function, array, args: dict = None, max_workers=8):
    return_value = []
    try:
        args = args or {}
        logging.debug(f"Scheduling parallel threads for {function.__name__}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for element in array:
                future = executor.submit(function, element, args)
                futures.append(future)

        concurrent.futures.wait(futures)
        logging.debug(f"All parallel threads for {function.__name__} completed")
        for future in futures:
            if future.result():
                result = future.result()
                if result:
                    return_value.append(result)
    except Exception as e:
        logging.exception(e)
    return return_value


if __name__ == "__main__":
    def some_function(var, args):
        print(var)
        return var


    inputs = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    returned_data = run_parallel(some_function, inputs, max_workers=16)
    print(f'returned_data: {returned_data}')
