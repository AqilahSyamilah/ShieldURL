<?php
$result = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Collect features from the form
    $features = [
        "UsingIP" => (int)$_POST["UsingIP"],
        "LongURL" => (int)$_POST["LongURL"],
        "ShortURL" => (int)$_POST["ShortURL"],
        "Symbol@" => (int)$_POST["Symbol@"],
        "Redirecting//" => (int)$_POST["Redirecting//"],
        "PrefixSuffix-" => (int)$_POST["PrefixSuffix-"],
        "SubDomains" => (int)$_POST["SubDomains"],
        "HTTPS" => (int)$_POST["HTTPS"],
        "DomainRegLen" => (int)$_POST["DomainRegLen"],
        "Favicon" => (int)$_POST["Favicon"],
        "NonStdPort" => (int)$_POST["NonStdPort"],
        "HTTPSDomainURL" => (int)$_POST["HTTPSDomainURL"],
        "RequestURL" => (int)$_POST["RequestURL"],
        "AnchorURL" => (int)$_POST["AnchorURL"],
        "LinksInScriptTags" => (int)$_POST["LinksInScriptTags"],
        "ServerFormHandler" => (int)$_POST["ServerFormHandler"],
        "InfoEmail" => (int)$_POST["InfoEmail"],
        "AbnormalURL" => (int)$_POST["AbnormalURL"],
        "WebsiteForwarding" => (int)$_POST["WebsiteForwarding"],
        "StatusBarCust" => (int)$_POST["StatusBarCust"],
        "DisableRightClick" => (int)$_POST["DisableRightClick"],
        "UsingPopupWindow" => (int)$_POST["UsingPopupWindow"],
        "IframeRedirection" => (int)$_POST["IframeRedirection"],
        "AgeofDomain" => (int)$_POST["AgeofDomain"],
        "DNSRecording" => (int)$_POST["DNSRecording"],
        "WebsiteTraffic" => (int)$_POST["WebsiteTraffic"],
        "PageRank" => (int)$_POST["PageRank"],
        "GoogleIndex" => (int)$_POST["GoogleIndex"],
        "LinksPointingToPage" => (int)$_POST["LinksPointingToPage"],
        "StatsReport" => (int)$_POST["StatsReport"]
    ];

    $json = json_encode($features);

    // IMPORTANT: use full python path if needed
    $python = "python";
    $script = "app\\predict_from_json.py";

    $cmd = $python . " " . escapeshellarg($script) . " " . escapeshellarg($json);
    $result = trim(shell_exec($cmd));
}
?>

<!DOCTYPE html>
<html>
<head>
  <title>ShieldURL Basic Scan</title>
</head>
<body>
  <h2>ShieldURL Basic Scan (Feature-based)</h2>

  <form method="POST">
    <?php
      // Dropdown values commonly used in this dataset: -1, 0, 1
      function dropdown($name) {
          echo "<label>$name: </label>";
          echo "<select name='".htmlspecialchars($name, ENT_QUOTES)."'>";
          foreach ([-1,0,1] as $v) {
              echo "<option value='$v'>$v</option>";
          }
          echo "</select><br><br>";
      }

      $fields = [
        "UsingIP","LongURL","ShortURL","Symbol@","Redirecting//","PrefixSuffix-","SubDomains","HTTPS",
        "DomainRegLen","Favicon","NonStdPort","HTTPSDomainURL","RequestURL","AnchorURL","LinksInScriptTags",
        "ServerFormHandler","InfoEmail","AbnormalURL","WebsiteForwarding","StatusBarCust","DisableRightClick",
        "UsingPopupWindow","IframeRedirection","AgeofDomain","DNSRecording","WebsiteTraffic","PageRank",
        "GoogleIndex","LinksPointingToPage","StatsReport"
      ];

      foreach ($fields as $f) dropdown($f);
    ?>
    <button type="submit">Scan</button>
  </form>

  <?php if ($result): ?>
    <h3>Result: <?php echo htmlspecialchars($result); ?></h3>
  <?php endif; ?>
</body>
</html>
