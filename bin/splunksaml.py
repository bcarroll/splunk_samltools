import re,sys,time,splunk.Intersplunk
import urllib           # urldecoding
import zlib             # uncompressing
import base64           # base64 decoding
import xml.dom.minidom  # XML tidying

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
        try:
                fields, argvals = splunk.Intersplunk.getKeywordsAndOptions()
                type            = argvals.get("type", "authnrequest")
                pretty_xml      = argvals.get("format", "raw")
    
                if type == "authnrequest":
                        samlfunct = decode_authnrequest
                if type == "response":
                        samlfunct = decode_response

                for _result in results:
                        for _field in fields:
                                if _field in _result:
                                        _result[_field] = samlfunct(_result[_field])
    
                splunk.Intersplunk.outputResults(results)
    
        except:
                import traceback
                stack   = traceback.format_exc()
                results = splunk.Intersplunk.generateErrorResults("Error : Traceback: " + str(stack))
    
results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()

results = dosaml(results, settings)
