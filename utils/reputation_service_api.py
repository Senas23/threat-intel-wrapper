import logging
import requests
import json
from utils.exceptions import StatusCodeException
from utils.logger import get_logger

#service, resource, client_key, verbose
class reputation_service_api():
    def __init__(
        self,
        api_key,
        verbose=False,
        base_url='https://rep.checkpoint.com/',
        prettyPrint=False
    ):
        """
        Reputation API Python Wrapper.

        Available Functions
        - test_connect              Provides a method to test connectivity
        - get_domain                Domain information endpoints that return various information about domains.

        Usage:
        rep = reputation_service_api(client_key='yourclientapikey')

        rep.function_name(valid_variables)
        """

        # Create Base URL variable to allow for updates in the future
        self.base_url = base_url
        # Create API Key variable to pass into each request
        self.api_key = api_key
        # Create Logging Verbose variable
        self.verbose = verbose
        # Create Pretty Print variable
        self.prettyPrint = prettyPrint
        # Set Logger name and level    
        self.logger = (get_logger(__name__, logging.DEBUG) if verbose else get_logger(__name__))

        self.get_token()

        # Initiate Ping to Security Trails
        #self.ping = self.session.get(base_url + "ping")

        # Request failed returning false and logging an error
        #if self.ping.status_code != 200:
        #    logger.error(
        #        "Error connecting to Security Trails, error message: {}".format(
        #            self.ping.text))

    def get_token(self):
        self.logger.debug('[+] First, let\'s get token from rep-auth')
        token_res = requests.get('{}/rep-auth/service/v1.0/request'.format(self.base_url),
                                 headers={'Client-Key': self.api_key})
        if token_res.status_code != 200:
            self.logger.error(
              '[-] Error getting token. Code: {} Message: {}'.format(
                token_res.status_code, token_res.text))
            raise StatusCodeException(token_res.status_code)
        self.token = token_res.content
        self.logger.debug('[+] Success! Token: {}'.format(self.token))

    def query(self, service, resource) -> dict:
        try:
          # Check to see if API Key is present
          if service not in ['url', 'file', 'ip']:
              raise Exception("Incorrect service provided {}.\nAvailable only [url, file, ip]")
          self.logger.debug('[+] Now, let\'s query reputation')
          self.logger.debug('[+] Base_URL: {}'.format(self.base_url))
          self.logger.debug('[+] Service: {}'.format(service))
          self.logger.debug('[+] Resource: {}'.format(resource))
          rep_res = requests.post('{}/{}-rep/service/v2.0/query?resource={}'.format(
            self.base_url, service, resource),
            json={
              'request': [{'resource': resource}]
              }, headers={'Client-Key': self.api_key, 'token': self.token})
          if rep_res.status_code != 200:
              raise StatusCodeException(rep_res.status_code)
          self.logger.debug('success!')
          self.logger.debug('your response is:\n{}\n'.format(json.dumps(rep_res.json(), indent=2)))
          #self.logger.debug('\n{}'.format(json.dumps(rep_res.json(), indent=2)))
          response = rep_res.json()['response'][0]
          self.response = response
          risk = response['risk']
          severity = response['reputation']['severity']
          classification = response['reputation']['classification']
          confidence = response['reputation']['confidence']
          #self.logger.info('{} is {} with risk {}/100'.format(resource, classification, risk))
          return dict({'Severity': severity, 'Classification': classification, \
            'Risk': risk, 'Confidence': confidence})
        except StatusCodeException as e:
            print(e)
            pass
