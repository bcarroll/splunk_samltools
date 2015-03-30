import re,sys,time,splunk.Intersplunk
import urllib           # urldecoding
import zlib             # uncompressing
import base64           # base64 decoding
import xml.dom.minidom  # XML tidying
import logging, logging.handlers
#import os,platform,json,pprint, StringIO, csv
import unicodedata

LOGFILE = '/opt/splunk/var/log/splunk/saml_utilities.log'
LOGLEVEL = 'DEBUG'

def setup_logger():
        logger = logging.getLogger('SAML_Utilities')
        logger.setLevel(logging.DEBUG)
        file_handler = logging.handlers.RotatingFileHandler(LOGFILE)
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        return(logger)

def set_loglevel(logger,LOGLEVEL):
        if LOGLEVEL == 'DEBUG':
                logger.setLevel(logging.DEBUG)
        if LOGLEVEL == 'INFO':
                logger.setLevel(logging.INFO)
        if LOGLEVEL == 'WARN':
                logger.setLevel(logging.WARN)
        if LOGLEVEL == 'ERROR':
                logger.setLevel(logging.ERROR)
        return()

def decode_response(response,pretty_xml=False):
        return()

def decode_authnrequest(authn_request,pretty_xml=False):
        #       AuthnRequest is always deflated, base64 encoded and url-escaped.
        #               Parameters
        #                       authn_request : deflated, base64 encoded and url-escaped SAML AuthnRequest XML document/string
        #                       pretty_xml    : Return pretty/tidy SAMLRequest XML (Multi-line, indented) (Default is False)
        #               Return
        #                       The decoded AuthnRequest if successful, "Error decoding SAMLRequest" on failure.
        #
        if (authn_request):
                urldecoded_SAMLRequest   = urllib.unquote(authn_request)
                #urldecoded_SAMLRequest  = urldecoded_SAMLRequest.strip('SAMLRequest=')
                b64decoded_SAMLRequest   = base64.b64decode(urldecoded_SAMLRequest)
                decompressed_SAMLRequest = zlib.decompress(b64decoded_SAMLRequest, -15)
        else:
                return()

        if decompressed_SAMLRequest is None:
                return "Error decoding SAMLRequest"
        else:
                if pretty_xml:
                        _xml_doc = xml.dom.minidom.parseString(decompressed_SAMLRequest)
                        xml_pretty = _xml_doc.toprettyxml(indent='\t')
                        return(xml_pretty)
                else:
                        return decompressed_SAMLRequest
                        
def dosaml(results,settings):
        #logger.debug( "dosaml(%s,%s)" % (results,settings) )
        try:
                fields, argvals = splunk.Intersplunk.getKeywordsAndOptions()
                saml_type       = argvals.get("type", "authnrequest")
                pretty_xml      = argvals.get("format", "raw")
                extract_fields  = argvals.get("extract", True)
    
                if saml_type == "authnrequest":
                        samlfunct = decode_authnrequest
                if saml_type == "response":
                        samlfunct = decode_response

                for _result in results:
                        for _field in fields:
                                if _field in _result:
                                        if pretty_xml == "tidy":
                                                _result[_field] = samlfunct(_result[_field],True)       
                                                if (extract_fields):
                                                        _result.update(do_extract_fields(_result[_field], saml_type))
                                        else:
                                                _result[_field] = samlfunct(_result[_field])
                                                if (extract_fields):
                                                        _result.update(do_extract_fields(_result[_field], saml_type))

                #append extracted_saml_fields to results
                splunk.Intersplunk.outputResults(results)
    
        except:
                import traceback
                stack   = traceback.format_exc()
                results = splunk.Intersplunk.generateErrorResults("Error : Traceback: " + str(stack))
                logger.error(results)

def do_extract_fields(SAMLMessage,saml_type):
        logger.debug('do_extract_fields()')
        extracted_fields = ""
        if saml_type == "authnrequest":
                return( saml_authnrequest_extractFields(SAMLMessage) )
        if saml_type == "response":
                return( saml_response_extractFields(SAMLMessage) )
        return(False)

def saml_response_extractFields(assertion):
        # TODO
        return(False)

def saml_authnrequest_extractFields(authnrequest):
        logger.debug('saml_authnrequest()')
        import xml.dom.minidom
        DOMTree = xml.dom.minidom.parseString(authnrequest)
        saml_document = DOMTree.documentElement
        saml_request = {}
        saml_request['SAMLRequest_Protocol']                 = ""
        saml_request['SAMLRequest_ACSURL']                   = ""
        saml_request['SAMLRequest_Destination']              = ""
        saml_request['SAMLRequest_Consent']                  = ""
        saml_request['SAMLRequest_ID']                       = ""
        saml_request['SAMLRequest_Issue_Instant']            = ""
        saml_request['SAMLRequest_Protocol_Binding']         = ""
        saml_request['SAMLRequest_Version']                  = ""
        saml_request['SAMLRequest_Issuer_Namespace']         = ""
        saml_request['SAMLRequest_Issuer']                   = ""
        saml_request['SAMLRequest_NameIDPolicy_AllowCreate'] = ""
        saml_request['SAMLRequest_Protocol']                 = saml_document.getAttribute("xmlns:samlp").encode()
        saml_request['SAMLRequest_ACSURL']                   = saml_document.getAttribute("AssertionConsumerServiceURL").encode()
        saml_request['SAMLRequest_Destination']              = saml_document.getAttribute("Destination").encode()
        saml_request['SAMLRequest_Consent']                  = saml_document.getAttribute("Consent").encode()
        saml_request['SAMLRequest_ID']                       = saml_document.getAttribute("ID").encode().encode()
        saml_request['SAMLRequest_Issue_Instant']            = saml_document.getAttribute("IssueInstant").encode()
        saml_request['SAMLRequest_Protocol_Binding']         = saml_document.getAttribute("ProtocolBinding").encode()
        saml_request['SAMLRequest_Version']                  = saml_document.getAttribute("Version").encode()
        if (saml_document.getElementsByTagName("saml:Issuer")):
                saml_request['SAMLRequest_Issuer_Namespace'] = saml_document.getElementsByTagName("saml:Issuer")[0].getAttribute("xmlns:saml").encode()
                saml_request['SAMLRequest_Issuer']           = saml_document.getElementsByTagName("saml:Issuer")[0].childNodes[0].data.encode()
        if (saml_document.getElementsByTagName("Issuer")):
                saml_request['SAMLRequest_Issuer_Namespace'] = saml_document.getElementsByTagName("Issuer")[0].getAttribute("xmlns").encode()
                saml_request['SAMLRequest_Issuer']           = saml_document.getElementsByTagName("Issuer")[0].childNodes[0].data.encode()
        saml_request['SAMLRequest_NameIDPolicy_AllowCreate'] = saml_document.getElementsByTagName("samlp:NameIDPolicy")[0].getAttribute("AllowCreate").encode()
        logger.debug(saml_request)
        return(saml_request)




logger = setup_logger()    
results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()
results = dosaml(results, settings)
