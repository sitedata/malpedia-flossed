import requests
from collections import Counter

from intelligence.base import *
from malcat import KesakodeMatch, Detection
from kesakode import KesakodeExternalResult

# change to your own instance if the public one has insufficient quota for you
URL = "https://strings.malpedia.io/api/query"


def generateStringHits(families):
    num_families = sum([1 for family in families if "lib." not in family])
    num_libraries = sum([1 for family in families if "lib." in family])
    if len(families) < 5:
        matched_string = f"{len(families):>4d} matches ({', '.join(sorted(families))})"
    else:
        matched_string = f"{len(families):>4d} matches ({num_families} families, {num_libraries} libraries)"
    results = [KesakodeMatch.Hit(
                name=f"{matched_string}",
                level = Detection.Level.MALWARE if not num_libraries else Detection.Level.LIBRARY,
                score = 100,
                symbol = ""
            )]
    return results


class MalpediaFlossed(OnlineChecker):
    """ 
    This plugin looks up all strings in the given binary against a MalpediaFLOSSed web service
    and renders the results into the Kesakode GUI.
    """

    name = "MalpediaFLOSSed"
    kesakode_menu_name = "MalpediaFLOSSed String Resolver"

    options = {
        "key": ("", "MalpediaFLOSSed works with any key, but please consider hosting your own instance in case of heavy use."),
    }
 
    def kesakode(self, analysis, fuzzy_matching=False):
        result = KesakodeExternalResult() 

        query_string = ",".join(f"\"{string}\"" for string in analysis.strings)
        response = requests.post(f"{URL}", data=query_string, verify=self.options.get("ssl_verify", True))
        response_data = {}
        results_by_string = {}
        family_counts = Counter()
        if response.ok:
            response_data = response.json()
            status = response_data.get("status", "failed")
            if status != "successful":
                return result
            for flossed_result in response_data.get("data", []):
                results_by_string[flossed_result["string"]] = flossed_result
                if flossed_result["matched"]:
                    for family in flossed_result["families"]:
                        family_counts[family] += 1
            for i, s in enumerate(analysis.strings):
                if str(s) in results_by_string:
                    kesakode_result = []
                    flossed_result = results_by_string[str(s)]
                    if flossed_result["matched"]:
                        kesakode_result.extend(generateStringHits(flossed_result["families"]))
                    else:
                        kesakode_result.append(KesakodeMatch.Hit(
                            name=f"{0:>4d} matches",
                            level = Detection.Level.UNKNOWN,
                            score = 100,
                            symbol = ""
                        ))
                    result[s] = kesakode_result
        
        result.verdict = {}
        for family, count in family_counts.most_common(5):
            result.verdict[family] = 100.0 * count / len(results_by_string)
        return result

