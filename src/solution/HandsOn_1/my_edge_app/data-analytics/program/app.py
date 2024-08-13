# Copyright (c) Siemens 2021
# This file is subject to the terms and conditions of the MIT License.  
# See LICENSE file in the top-level directory.

''' Main python module for Data Analytics service '''
import time
import os
import sys
import logging
import data_analytics

MAIN_LOOP_SLEEP_TIME = 0.5


def main():

    """ Initialize data-analytics """
    
    # configures basic logger
    logger = logging.getLogger( __name__ )
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s | %(name)s | %(levelname)s | %(message)s')
    handler.setFormatter(formatter)    
    logger.addHandler(handler)


    logger.info('Starting data-analytics service ...')
    analytics = data_analytics.DataAnalyzer(logger.name)
    analytics.handle_data()
    
    while True:
      time.sleep(MAIN_LOOP_SLEEP_TIME)


if __name__ == '__main__':
    main()
