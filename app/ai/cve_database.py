"""
CVE Database Connector

Uses NVD API
Fetches vulnerability information
"""


import requests



class CVEDatabase:



    def __init__(self):

        self.base_url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
        )



    def search_cve(self, keyword):


        params = {

            "keywordSearch": keyword,

            "resultsPerPage": 5

        }


        try:

            response = requests.get(
                self.base_url,
                params=params,
                timeout=10
            )


            if response.status_code != 200:

                return []


            data = response.json()


            vulnerabilities = []


            for item in data.get(
                "vulnerabilities",
                []
            ):


                cve = item["cve"]


                cve_id = cve.get(
                    "id"
                )


                description = (
                    cve
                    .get("descriptions",[{}])[0]
                    .get("value","")
                )


                vulnerabilities.append({

                    "cve_id": cve_id,

                    "description": description

                })



            return vulnerabilities



        except Exception as e:


            print(
                "CVE Lookup Error:",
                e
            )


            return []