# https://github.com/dbrennand/virustotal-python

import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode
import pandas as pd

v_url = "bit.ly/shopeebigsale662"

with virustotal_python.Virustotal("<your_API_key>") as vtotal:
    try:
        resp = vtotal.request("urls", data={"url": url}, method="POST")
        # Safe encode URL in base64 format
        # https://developers.virustotal.com/reference/url
        url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
        report = vtotal.request(f"urls/{url_id}")
        # pprint(report.object_type)
        # pprint(report.data)
        v_result_url = report.data['attributes']['last_analysis_stats']
        print(v_url)
        print(v_result_url)
        
    except virustotal_python.VirustotalError as err:
        print(f"Failed to send URL: {url} for analysis and get the report: {err}")

vt3 = pd.DataFrame(v_result_url, index=[0]).reset_index(drop=True)
count = (((vt3['malicious']+vt3['suspicious']+vt3['undetected']) / (vt3['harmless']+vt3['malicious']+vt3['suspicious']+vt3['undetected']+vt3['timeout'])) * 100)
print('Persentase Tidak Aman: '+ str(round(count[0], 1)) + ' %')
