from pymisp import PyMISP, MISPEvent, MISPAttribute
from virustotal_public import handler

# The URL of the MISP instance to connect to
misp_url = 'Your MISP URL'
# Can be found in the MISP web interface under
# http://+MISP_URL+/users/view/me -> Authkey
misp_key = 'Your MISP key'
VTPublic_APIkey = 'Your virustotal public API key'
misp_verifycert = False
misp = PyMISP(misp_url, misp_key, misp_verifycert)

def fetch_misp_object(EVENTid):

    event_id = EVENTid

    # Fetch by ID
    event = misp.get_event(event_id)
    for ioc in event['Event']['Attribute']:
        ioc_value = ioc['value']
        print('Extracted IoC is "' + str(ioc_value) + '"')
        # change_distribution(event)
        enrich(ioc_value)

# change Distribution to "Your organisation only" to ignore pull requests.
# However, Pull request pulls proposal data.
# If you need to change the distribution, please uncomment them.
# def change_distribution(event):
#     misp_event = MISPEvent()
#     misp_event.load(event)
#     misp_event.distribution = 0
#     misp.update_event(misp_event)
#     print('Distribution is changed to "Your organisation only" to lock this Event.')

def enrich(ioc_value):
    q = r'{"config": {"apikey": "' + VTPublic_APIkey + '"}, "attribute": {"value": "' + ioc_value + '", "type": "domain"}}'

    results = handler(q)

    # for result in results['results']['Attribute']:
        # print(result)

    for result in results['results']['Object']:
        for result in result['Attribute']:
            if result['type'] == 'ip-dst':
                type = result['type']
                value = result['value']
                category = result['category']
                print('Enriched! type:' + str(result['type']) + ', value: ' + str(result['value']) + ', category' + str(result['category']))
                propose(type, value, category)

def propose(type, value, category):
    attr_type = type
    value = value
    category = category
    to_ids = False

    # Attribute data already defined
    attribute = MISPAttribute()
    attribute.type = attr_type
    attribute.value = value
    attribute.category = category
    attribute.to_ids = to_ids

    event_id = EVENTid
    proposal = misp.add_attribute_proposal(event_id, attribute)
    print('Proposed!')


EVENTid = 241
fetch_misp_object(EVENTid)
