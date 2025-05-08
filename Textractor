import json
import os
import hmac
import hashlib
import io
from xml.sax.saxutils import escape
from pyPreservica import *
from textractor import Textractor
from PIL import Image

os.environ["LD_LIBRARY_PATH"] = f"/opt/python/bin/:{os.environ['LD_LIBRARY_PATH']}"
os.environ["PATH"] = f"/opt/python/bin/:{os.environ['PATH']}"

client = EntityAPI()



os.environ['AWS_REGION'] = "eu-west-1"

def send(asset: Asset, document: str):

    xml_doc = f"""<xip:MetadataContainer xmlns="http://www.preservica.com/metadata/group/ai_ocr_text" schemaUri="http://www.preservica.com/metadata/group/ai_ocr_text" xmlns:xip="http://preservica.com/XIP/v7.7">
    <xip:Entity>{asset.reference}</xip:Entity>
        <xip:Content>
           {document}
        </xip:Content>
    </xip:MetadataContainer>"""

    headers = {HEADER_TOKEN: client.token, 'Content-Type': 'application/xml;charset=UTF-8'}
    end_point = f"/{asset.path}/{asset.reference}/metadata"
    request = requests.post(f'{client.protocol}://{client.server}/api/entity{end_point}', data=xml_doc,
                                    headers=headers)

def ocr_asset(asset: Asset):
    xml.etree.ElementTree.register_namespace("", "http://www.preservica.com/metadata/group/ai_ocr_text")
    xml_response = """<ai_ocr_text xmlns="http://www.preservica.com/metadata/group/ai_ocr_text" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <text>$OCR$</text>
    </ai_ocr_text>"""

    extractor = Textractor(region_name="eu-west-1")
    for bs in client.bitstreams_for_asset(asset):
        if (bs.filename.lower().endswith("png")) or (bs.filename.lower().endswith("jpg")):
            image = Image.open(client.bitstream_bytes(bs))
            document = extractor.detect_document_text(file_source=image)
            xml_response = xml_response.replace("$OCR$", escape(document.text))
            print(xml_response)
            send(asset, xml_response)
            break
        
def lambda_handler(event, context):
    secret_key = os.environ.get('PRES_SECRET_KEY')
    print("Text Extract Lambda")
    if 'queryStringParameters' in event:
        if event['queryStringParameters'] is not None:
            if 'challengeCode' in event['queryStringParameters']:
                message = event['queryStringParameters']['challengeCode']
                signature = hmac.new(key=bytes(secret_key, 'latin-1'), msg=bytes(message, 'latin-1'),
                                     digestmod=hashlib.sha256).hexdigest()
                return {
                    "statusCode": 200,
                    "headers": {
                        "Content-Type": "application/json"
                    },
                    "body": json.dumps({
                        "challengeCode": f"{message}", "challengeResponse": f"{signature}"})
                }
    if 'Preservica-Signature' in event['headers']:
        verify_body = f"preservica-webhook-auth{event['body']}"
        signature = hmac.new(key=bytes(secret_key, 'latin-1'), msg=bytes(verify_body, 'latin-1'),
                             digestmod=hashlib.sha256).hexdigest()
        doc = json.loads(event['body'])

        if signature == event['headers']['Preservica-Signature']:      
            for reference in list(doc['events']):
                print(f"Web hook event for entity {reference}")
                entityRef = reference['entityRef']
                entityType = reference['entityType']
                if entityType == 'IO':
                    asset = client.asset(entityRef)
                    ocr_asset(asset)
                if entityType == 'SO':
                    folder = client.folder(entityRef)
                    print(folder)
                
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps(event['body'])
        }
