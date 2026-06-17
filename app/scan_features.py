try:
    from .predict_from_features import predict_features
except ImportError:
    from predict_from_features import predict_features


def scan_from_features(features: dict):
    result = predict_features(features)
    return result["status"]


if __name__ == "__main__":
    # Example input for manual model testing. The main app uses scan_url.run_scan().
    sample = {
        "UsingIP": 0,
        "LongURL": 1,
        "ShortURL": 0,
        "Symbol@": 0,
        "Redirecting//": 0,
        "PrefixSuffix-": 1,
        "SubDomains": 1,
        "HTTPS": 1,
        "DomainRegLen": 0,
        "Favicon": 0,
        "NonStdPort": 0,
        "HTTPSDomainURL": 0,
        "RequestURL": 1,
        "AnchorURL": 1,
        "LinksInScriptTags": 0,
        "ServerFormHandler": 0,
        "InfoEmail": 0,
        "AbnormalURL": 1,
        "WebsiteForwarding": 0,
        "StatusBarCust": 0,
        "DisableRightClick": 0,
        "UsingPopupWindow": 0,
        "IframeRedirection": 0,
        "AgeofDomain": 1,
        "DNSRecording": 1,
        "WebsiteTraffic": 0,
        "PageRank": 0,
        "GoogleIndex": 1,
        "LinksPointingToPage": 0,
        "StatsReport": 0,
    }
    print("Result:", scan_from_features(sample))
