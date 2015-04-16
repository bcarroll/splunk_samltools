import re, sys, time, splunk.Intersplunk
import urllib, zlib, base64
import logging, logging.handlers
try:
    import xml.etree.cElementTree as xml
except ImportError:
    import xml.etree.ElementTree as xml

def setup_logger(LOGGER_NAME,LOGFILE_NAME):
    logger       = logging.getLogger(LOGGER_NAME)
    file_handler = logging.handlers.RotatingFileHandler(LOGFILE_NAME)
    formatter    = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.setLevel(logging.ERROR)
    return(logger)

def set_logger_level(LOGGER_LEVEL='NOTSET'):
    logger.info('set_logger_level(' + LOGGER_LEVEL + ') called...')
    if LOGGER_LEVEL   == 'NOTSET':
        logger.setLevel(logging.NOTSET)
    elif LOGGER_LEVEL == 'DEBUG':
        logger.setLevel(logging.DEBUG)
    elif LOGGER_LEVEL == 'INFO':
        logger.setLevel(logging.INFO)
    elif LOGGER_LEVEL == 'WARNING':
        logger.setLevel(logging.WARNING)
    elif LOGGER_LEVEL == 'ERROR':
        logger.setLevel(logging.ERROR)
    elif LOGGER_LEVEL == 'CRITICAL':
        logger.setLevel(logging.CRITICAL)
    return(None)

def uri_unescape(string):
    #   Parameters
    #       string : URI escaped string
    #   Return
    #       URI unescaped string
    logger.debug('uri_unescape() called...')
    uri_unescaped_string = None
    try:
        uri_unescaped_string = urllib.unquote(string) # urldecode Base64 encoded SAML AuthnRequest
    except:
        return(string)
    return(uri_unescaped_string)

def base64_decode(string):
    #   Parameters
    #       string : Base64 encoded string
    #   Return
    #       decoded/plain text string
    logger.debug('base64_decode() called...')
    base64_decoded_string = None
    try:
        base64_decoded_string = base64.b64decode(string) # decode Base64 encoded XML document
    except:
        return(string)
    return(base64_decoded_string)

def zlib_decompress(string):
    #   Parameters
    #       string : zlib compressed string
    #   Return
    #       inflated/uncompressed string
    zlib_decompressed_string = None
    try:
        zlib_decompressed_string = zlib.decompress(string, -15) # uncompress XML document
    except:
        return(string)
    return(zlib_decompressed_string)

def xml2dict(xmlstring, prepend_string=None, remove_namespace=True):
    logger.debug('xml2dict() called...')
    #   Parameters
    #       xmlstring        : XML document
    #       prepend_string   : String to add to the beginning of each key
    #       remove_namespace : If set to True (default), the XML namespace is removed from key names
    #   Return
    #       xmlkv            : dict of XML element names and values.  XML tags and attribute names are concatenated to form the returned key

    # TODO: dict keys should indicate the complete XML hierarchy.
    #   Example: <Root><Element1><Element2 Attribute="stuff" /></Element1></Root> = xmlkv['Root_Element1_Element2_Attribute']

    xmlkv    = {}
    try:
        root     = xml.fromstring(xmlstring)
        tree     = xml.ElementTree(root)
    except:
        logger.warning('Error parsing XML:' + xmlstring)
        return(None)

    root_tag = repr(root).split('}',1)[1].split('\'',1)[0].replace('\n','').replace('\r','') # strip XML namespace and remove newline characters
    if prepend_string is not None:
        root_tag = prepend_string + root_tag
    for element in tree.iter():
        if remove_namespace == True:
            if '}' in element.tag:
                element.tag = element.tag.split('}',1)[1].replace('\n','').replace('\r','') # strip XML namespaces and remove newline characters
        try:
            if element.text:
                key = root_tag + '_' + element.tag
                val = element.text = element.text.replace('\n','').replace('\r','') # remove newline characters
                if val.strip():
                    xmlkv[key] = val
            elif element.attrib is not None:
                for attribute in element.attrib:
                    if attribute is not None:
                        key = root_tag + '_' + element.tag + '_' + attribute.replace('\n','').replace('\r','') # remove newline characters
                        key = key.replace('__','_') # replace 2 consecutive underscores with a single underscore (this only happens with the tag or attribute name begins with an underscore)
                        val = element.attrib.get(attribute).replace('\n','').replace('\r','') # remove newline characters
                        if val.strip():
                            xmlkv[key] = val
        except:
            logger.warning(root_tag + '_' + element.tag, element.text)
            continue
    return(xmlkv)

def dosaml(results,settings):
    #   Parameters
    #       string : SAML message
    #       type   : type of SAML message (AuthnRequest, Response, AttributeQuery, etc...)  If type is not provided we will try to detect it
    #   Return
    #       dict containing SAML message key/value pairs
    try:
        fields, argvals = splunk.Intersplunk.getKeywordsAndOptions()

        for _result in results:
            for _field in fields:
                if _field in _result:
                    saml_message      = _result[_field]
                    saml_message      = uri_unescape(saml_message)
                    saml_message      = base64_decode(saml_message)
                    saml_message      = zlib_decompress(saml_message)
                    saml_message_dict = xml2dict(saml_message,'SAML')
                    if saml_message_dict is not None:
                        logger.debug(repr(saml_message_dict))
                        _result.update(saml_message_dict) # create new fields with SAML attributes
        #append extracted_saml_fields to results
        splunk.Intersplunk.outputResults(results)
    except:
        import traceback
        stack   = traceback.format_exc()
        results = splunk.Intersplunk.generateErrorResults("Error : Traceback: " + str(stack))
        logger.error("Error : " + str(stack))

logger = setup_logger('SplunkSAML','/opt/splunk/var/log/splunk/saml_utils.log')
#set_logger_level('DEBUG')
results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()
results = dosaml(results, settings)
