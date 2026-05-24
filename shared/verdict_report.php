<?php

function shield_text($value)
{
    return trim((string)($value ?? ''));
}

function shield_list($value)
{
    if ($value === null || $value === '') {
        return [];
    }
    if (is_string($value)) {
        $decoded = json_decode($value, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            return shield_list($decoded);
        }
        return array_values(array_filter(array_map('trim', preg_split('/\r\n|\r|\n|;/', $value))));
    }
    if (!is_array($value)) {
        return [shield_text($value)];
    }
    $out = [];
    foreach ($value as $item) {
        if (is_array($item)) {
            $text = $item['action'] ?? $item['step'] ?? $item['description'] ?? $item['name'] ?? '';
            $out[] = $text !== '' ? shield_text($text) : $item;
        } elseif ($item !== null && $item !== '') {
            $out[] = shield_text($item);
        }
    }
    return array_values(array_filter($out, fn($item) => $item !== '' && $item !== null));
}

function shield_unique_list($values)
{
    $out = [];
    $seen = [];
    foreach (shield_list($values) as $item) {
        $key = strtolower(is_array($item) ? json_encode($item) : shield_text($item));
        if ($key === '' || isset($seen[$key])) {
            continue;
        }
        $seen[$key] = true;
        $out[] = $item;
    }
    return $out;
}

function shield_unique_raw_list($values)
{
    if (!is_array($values)) {
        return shield_list($values);
    }
    $out = [];
    $seen = [];
    foreach ($values as $item) {
        $key = strtolower(is_array($item) ? json_encode($item) : shield_text($item));
        if ($key === '' || isset($seen[$key])) {
            continue;
        }
        $seen[$key] = true;
        $out[] = $item;
    }
    return $out;
}

function shield_verdict_category($status = '', $displayStatus = '', $riskLevel = '', $phishingProbability = null, $selectedThreshold = null)
{
    $display = strtolower(str_replace('_', ' ', shield_text($displayStatus)));
    $status = strtolower(str_replace('_', ' ', shield_text($status)));
    $risk = strtolower(shield_text($riskLevel));
    $text = trim($display . ' ' . $status . ' ' . $risk);
    $probabilityProvided = $phishingProbability !== null && $phishingProbability !== '';
    $thresholdProvided = $selectedThreshold !== null && $selectedThreshold !== '';
    $probability = $probabilityProvided ? shield_unit_probability($phishingProbability) : null;
    $threshold = $thresholdProvided ? shield_unit_probability($selectedThreshold) : null;

    if ($threshold !== null && $probability !== null && $probability >= $threshold) {
        return 'phishing';
    }
    if (strpos($display, 'phishing') !== false || $status === 'phishing' || $risk === 'high') {
        return 'phishing';
    }
    if (strpos($display, 'potentially suspicious') !== false || strpos($display, 'suspicious') !== false || $status === 'suspicious' || $risk === 'medium') {
        return 'suspicious';
    }
    if (preg_match('/\b(safe|legitimate|low)\b/', $text)) {
        return 'safe';
    }
    return 'safe';
}

function shield_display_status($category, $displayStatus = '')
{
    $display = shield_text($displayStatus);
    if ($category === 'suspicious') {
        return 'Potentially Suspicious';
    }
    if ($category === 'phishing') {
        return 'Phishing';
    }
    return $display !== '' && stripos($display, 'safe') !== false ? $display : 'Safe';
}

function shield_unit_probability($value)
{
    if ($value === null || $value === '') {
        return 0.0;
    }
    $number = (float)$value;
    if ($number > 1) {
        $number = $number / 100;
    }
    return max(0.0, min(1.0, $number));
}

function shield_percent_text($value)
{
    return number_format(shield_unit_probability($value) * 100, 2) . '%';
}

function shield_dynamic_policy_text($category)
{
    if ($category === 'phishing') {
        return 'Phishing was detected by the URL model; confidence and risk level determine response severity.';
    }
    if ($category === 'suspicious') {
        return 'Several suspicious URL characteristics were identified during analysis.';
    }
    return 'No major phishing indicators were identified during analysis.';
}

function shield_mitre_tag($category, $existing = [])
{
    if ($category === 'safe') {
        return [];
    }
    if ($category === 'suspicious') {
        return ['Potentially Related: T1566.002 - Spearphishing Link'];
    }
    return [[
        'id' => 'T1566.002',
        'name' => 'Spearphishing Link',
        'rationale' => 'The URL was classified as phishing and may lure users through a deceptive link.',
    ]];
}

function shield_report_audience($audience = 'user')
{
    return strtolower((string)$audience) === 'admin' ? 'admin' : 'user';
}

function shield_interaction_status($clicked)
{
    if ($clicked === true || $clicked === 1 || $clicked === '1' || strtolower((string)$clicked) === 'true' || strtolower((string)$clicked) === 'yes') {
        return 'Accessed by user';
    }
    if ($clicked === false || $clicked === 0 || $clicked === '0' || strtolower((string)$clicked) === 'false' || strtolower((string)$clicked) === 'no') {
        return 'Not accessed by user';
    }
    return 'Not collected';
}

function shield_clicked_yes($clicked)
{
    return shield_interaction_status($clicked) === 'Accessed by user';
}

function shield_clicked_no($clicked)
{
    return shield_interaction_status($clicked) === 'Not accessed by user';
}

function shield_incident_summary($category, $clicked, $confidence, $url = '')
{
    $clickedYes = shield_clicked_yes($clicked);
    $clickedNo = shield_clicked_no($clicked);
    $target = shield_text($url) !== '' ? 'The submitted URL' : 'This URL';

    if ($category === 'safe') {
        if ($clickedYes) {
            return $target . ' was accessed and ShieldURL did not detect major phishing indicators in the URL structure or model output. The URL behavior appears consistent with a low-risk destination based on the available scan signals, with a phishing probability of ' . $confidence . '. No clear attack objective was identified, and user exposure risk remains low unless the page later redirects unexpectedly or requests credentials, OTPs, banking information, or personal data. Organizational impact is currently minimal, so urgency is low and no immediate incident response action is required beyond normal safe-browsing awareness.';
        }
        return $target . ' was assessed as low risk and no major phishing indicators were detected during analysis. Its observed URL behavior does not currently suggest credential harvesting, brand impersonation, malicious redirection, or a deceptive verification flow, and the displayed phishing probability is ' . $confidence . '. User exposure risk is low because no access or data entry was recorded, and organizational impact is limited unless the link is later reused in a suspicious campaign. Urgency is low; no credential reset or escalation is required unless a user later interacts with the page or notices suspicious behavior.';
    }

    if ($category === 'suspicious') {
        if ($clickedYes) {
            return $target . ' was accessed and ShieldURL detected suspicious URL characteristics, but the available evidence does not confirm phishing. The URL may behave like a cautionary link by leading users toward an unexpected login, account update, payment, or verification page where the possible attack objective is credential collection or sensitive data capture. User exposure risk depends on post-access activity and becomes significant if passwords, OTPs, banking information, or personal data were entered. Organizational impact is moderate because similar suspicious links can affect multiple users if shared internally, so urgency is medium: stop interacting with the page, verify the destination through an official source, and reset credentials only if sensitive information was submitted.';
        }
        return $target . ' contains suspicious characteristics, but the current evidence does not confirm it as phishing. The URL behavior should be treated as cautionary because it may redirect to or imitate a login, payment, account update, or verification page, with a possible attack objective of collecting credentials or sensitive information. User exposure risk is currently reduced because no access was recorded, but organizational impact could become moderate if the link is distributed to other users or appears in email, chat, or ticket workflows. Urgency is medium: do not enter sensitive information and ask IT/security to review the URL before allowing interaction.';
    }

    if ($clickedYes) {
        return $target . ' was accessed and classified as phishing by ShieldURL, indicating that the scan detected high-risk URL signals consistent with a deceptive or malicious destination. The URL may behave as a credential-harvesting or impersonation page by presenting a fake login, payment, account update, or verification flow, with the likely attack objective of stealing credentials, OTPs, banking details, or personal data. User exposure may have occurred if any sensitive information was entered after access, and organizational impact could include account compromise, unauthorized access, data exposure, or further phishing spread if the link reaches other users. Urgency is high: stop using the website immediately, report the incident to IT/security, reset affected credentials when data entry occurred, and monitor affected accounts for suspicious login or MFA activity.';
    }

    return $clickedNo
        ? $target . ' was classified as phishing by ShieldURL, but the user did not access it, so direct user exposure is currently reduced. The URL behavior should still be considered dangerous because it may imitate a trusted service, redirect to a deceptive login page, or present a fake verification flow with the attack objective of stealing credentials, OTPs, banking information, or personal data. Organizational impact remains high if the link is delivered to other users, reused in email campaigns, or allowed through internal communication channels. Urgency is high for containment: do not open the URL, report it to IT/security, remove or ignore the message containing the link, and require credential reset only if someone later interacts with the page or enters sensitive information.'
        : $target . ' was classified as phishing by ShieldURL and should not be opened or used. The URL may behave as a deceptive login, payment, account update, or verification page designed to collect credentials, OTPs, banking information, or other sensitive data. User exposure risk depends on whether anyone interacts with the page, while organizational impact could include compromised accounts, data exposure, and wider phishing propagation. Urgency is high: report the URL to IT/security, avoid sharing it with other users, and reset credentials only if interaction or data entry occurred.';
}

function shield_user_report_content($category, $clicked, $confidence)
{
    $clickedYes = shield_clicked_yes($clicked);
    $clickedNo = shield_clicked_no($clicked);

    if ($category === 'safe') {
        if ($clickedYes) {
            return [
                'summary' => shield_incident_summary('safe', $clicked, $confidence),
                'actions' => [
                    'Continue normal browsing.',
                    'Be cautious before entering sensitive information.',
                    'No credential reset is required.',
                ],
                'advisory' => 'No immediate action is required. Continue normal browsing and be cautious before entering sensitive information.',
            ];
        }
        return [
            'summary' => shield_incident_summary('safe', $clicked, $confidence),
            'actions' => [
                'No action required.',
                'Continue safe browsing practices.',
            ],
            'advisory' => 'No action is required. Continue safe browsing practices.',
        ];
    }

    if ($category === 'suspicious') {
        if ($clickedYes) {
            return [
                'summary' => shield_incident_summary('suspicious', $clicked, $confidence),
                'actions' => [
                    'Stop interacting with the page.',
                    'Do not enter passwords, OTPs, banking information, or personal data.',
                    'Reset password only if credentials were entered.',
                    'Report the URL to IT/security for verification.',
                ],
                'guidance' => [
                    'Use an official website or trusted bookmark instead.',
                    'Watch for redirects, fake login prompts, or unusual verification requests.',
                ],
                'advisory' => 'Stop interacting with the page. Reset credentials only if you entered them, and report the URL to IT/security for verification.',
            ];
        }
        return [
            'summary' => shield_incident_summary('suspicious', $clicked, $confidence),
            'actions' => [
                'Do not open the link.',
                'Verify the sender/source.',
                'Avoid entering sensitive information.',
                'No credential reset is required unless interaction occurred.',
            ],
            'guidance' => [
                'Use an official website or trusted bookmark instead.',
                'Ask IT/security to verify the link if it is work-related.',
            ],
            'advisory' => 'Do not open the link until verified. No credential reset is required unless interaction occurred.',
        ];
    }

    if ($clickedYes) {
        return [
            'summary' => shield_incident_summary('phishing', $clicked, $confidence),
            'actions' => [
                'Stop using the website immediately.',
                'Do not enter further information.',
                'Reset credentials if login details were entered.',
                'Enable MFA if available.',
                'Report the incident to IT/security.',
            ],
            'follow_up' => [
                'Monitor affected accounts for suspicious login attempts.',
                'Review recent account activity.',
                'Watch for unusual password reset or MFA notifications.',
                'Inform IT/security if any sensitive information was submitted.',
            ],
            'guidance' => [
                'Avoid reusing passwords across multiple accounts.',
                'Access sensitive services only through official websites or bookmarks.',
                'Verify domain names carefully before entering credentials.',
            ],
            'advisory' => 'Do not continue interacting with this website. If any sensitive information was entered, reset the affected account immediately and report the incident to IT/security.',
        ];
    }
    return [
        'summary' => shield_incident_summary('phishing', $clicked, $confidence),
        'actions' => [
            'Do not open the URL.',
            'Delete or ignore the message containing the link.',
            'Report the URL to IT/security.',
            'No credential reset is required unless the user later interacted with the site.',
        ],
        'follow_up' => [],
        'guidance' => [
            'Access sensitive services only through official websites or bookmarks.',
            'Verify domain names carefully before entering credentials.',
        ],
        'advisory' => 'Do not open the URL. Report it to IT/security; credential reset is not required unless you interacted with the site.',
    ];
}

function shield_build_verdict_report($context, $existingReport = [], $audience = 'user')
{
    $audience = shield_report_audience($audience);
    $status = $context['status'] ?? ($context['final_verdict'] ?? '');
    $display = $context['display_status'] ?? ($context['display_verdict'] ?? '');
    $risk = strtolower(shield_text($context['risk_level'] ?? 'low'));
    $selectedThreshold = $context['selected_threshold'] ?? ($context['lexical_threshold'] ?? 0.5);
    $probability = shield_unit_probability($context['phishing_probability'] ?? ($context['confidence_score'] ?? 0));
    $category = shield_verdict_category($status, $display, $risk, $probability, $selectedThreshold);
    $displayStatus = shield_display_status($category, $display);
    $confidence = shield_percent_text($probability);
    $url = shield_text($context['url'] ?? '');
    $clicked = $context['clicked'] ?? null;
    $interactionStatus = shield_interaction_status($clicked);

    $report = is_array($existingReport) ? $existingReport : [];
    $report['incident_details'] = [
        'url' => $url,
        'final_verdict' => ucfirst($category),
        'display_verdict' => $displayStatus,
        'risk_level' => $category === 'safe' ? 'low' : ($category === 'suspicious' ? 'medium' : ($probability < 0.70 ? 'medium' : 'high')),
        'confidence_score' => $confidence,
        'clicked' => $clicked,
        'user_interaction_status' => $interactionStatus,
        'audience' => $audience,
    ];

    if ($audience === 'user') {
        $content = shield_user_report_content($category, $clicked, $confidence);
        $report['incident_summary'] = $content['summary'];
        $report['detection_analysis'] = $category === 'safe'
            ? ['No major phishing indicators were detected.', 'Low phishing probability: ' . $confidence . '.']
            : ($category === 'suspicious'
                ? ['Suspicious indicators were detected, but phishing is not confirmed.', 'User exposure depends on whether sensitive information was entered.']
                : [
                    'Possible credential harvesting.',
                    'Possible brand impersonation.',
                    'Suspicious login or verification flow.',
                    'Social engineering lure.',
                ]);
        $report['severity_priority'] = [
            'severity' => $category === 'safe' ? 'Low' : (($category === 'suspicious' || $probability < 0.70) ? 'Medium' : 'High'),
            'priority' => $category === 'safe' ? 'Low' : (($category === 'suspicious' || $probability < 0.70) ? 'Medium' : 'High'),
            'confidence_comment' => ($category === 'safe' ? 'Low phishing probability: ' : 'Displayed phishing probability: ') . $confidence . '.',
            'possible_impact' => $category === 'safe' ? 'No immediate phishing impact was identified.' : 'Exposure is possible only if sensitive information was entered.',
        ];
        $report['containment_actions'] = $content['actions'];
        $report['eradication_recovery_actions'] = $content['follow_up'] ?? [];
        $report['post_incident_recommendations'] = $content['guidance'] ?? [];
        $report['user_advisory'] = $content['advisory'];
        $report['mitre_attack_mapping'] = shield_mitre_tag($category);
        $report['analyst_notes'] = 'User view uses simple action-based guidance and omits SOC-only NIST/MITRE details.';
    } elseif ($category === 'safe') {
        $report['incident_summary'] = shield_incident_summary('safe', $clicked, $confidence, $url);
        $report['detection_analysis'] = [
            'No major phishing indicators were detected in the current scan.',
            'The URL is assessed as low risk based on available URL signals.',
        ];
        $report['severity_priority'] = [
            'severity' => 'Low',
            'priority' => 'Low',
            'confidence_comment' => 'Displayed phishing probability is ' . $confidence . '.',
            'possible_impact' => 'No immediate phishing impact was identified from the current scan.',
        ];
        $report['containment_actions'] = [];
        $report['eradication_recovery_actions'] = [];
        $report['post_incident_recommendations'] = [];
        $report['user_advisory'] = 'No immediate action is required. Continue safe browsing and verify unexpected links before entering sensitive information.';
        $report['mitre_attack_mapping'] = [];
        $report['analyst_notes'] = 'MITRE ATT&CK: Not Applicable. NIST actions: Not Required. No containment or recovery actions required.';
    } elseif ($category === 'suspicious') {
        $report['incident_summary'] = shield_incident_summary('suspicious', $clicked, $confidence, $url);
        $report['detection_analysis'] = [
            'Suspicious signals require review before user interaction.',
            'Monitor for unexpected redirects, fake login prompts, or requests for sensitive information.',
        ];
        $report['severity_priority'] = [
            'severity' => 'Medium',
            'priority' => 'Medium',
            'confidence_comment' => 'Displayed phishing probability is ' . $confidence . '; treat this as a cautious review signal, not confirmed phishing.',
            'possible_impact' => 'Users could be exposed to deceptive content if the URL is unsafe.',
        ];
        $report['containment_actions'] = [
            'Verify the website legitimacy and source of the link before allowing sensitive user interaction.',
            'Avoid entering passwords, OTPs, banking information, or personal data until verified.',
        ];
        $report['eradication_recovery_actions'] = [
            'Review redirects, login prompts, and page behavior if users need to access the site.',
            shield_clicked_yes($clicked) ? 'Check whether sensitive information was entered before recommending credential reset.' : 'No credential reset is required unless user interaction occurred.',
        ];
        $report['post_incident_recommendations'] = [
            'Document the suspicious indicators and review outcome.',
            'Monitor DNS, proxy, email, and browser telemetry for repeated submissions or related activity.',
        ];
        $report['user_advisory'] = 'Verify the website before interacting. Do not enter passwords, OTPs, banking information, or personal data until the destination is confirmed legitimate.';
        $report['mitre_attack_mapping'] = shield_mitre_tag('suspicious', $report['mitre_attack_mapping'] ?? []);
        $report['analyst_notes'] = 'Suspicious verdict output uses cautious language and does not treat the URL as confirmed phishing.';
    } else {
        $report['incident_summary'] = shield_incident_summary('phishing', $clicked, $confidence, $url);
        $report['detection_analysis'] = [
            'Possible credential harvesting.',
            'Possible brand impersonation.',
            'Suspicious login or verification flow.',
            'Social engineering lure.',
        ];
        $report['severity_priority'] = [
            'severity' => $probability < 0.70 ? 'Medium' : 'High',
            'priority' => $probability < 0.70 ? 'Medium' : 'High',
            'confidence_comment' => 'Displayed phishing probability is ' . $confidence . '.',
            'possible_impact' => 'Users who interact with the URL may expose credentials or sensitive information.',
        ];
        $report['containment_actions'] = [
            'Block or quarantine the URL/domain in DNS, proxy, email, and browser controls where policy allows.',
            shield_clicked_yes($clicked) ? 'Identify affected users and warn them not to submit additional information.' : 'Warn users not to open the link and remove it from user-accessible messages.',
        ];
        $report['eradication_recovery_actions'] = [
            shield_clicked_yes($clicked) ? 'Monitor affected accounts for suspicious login attempts.' : 'Remove the phishing link from emails, tickets, chats, and other user-accessible locations.',
            shield_clicked_yes($clicked) ? 'Review recent account activity.' : 'No credential reset is required unless user interaction occurred.',
            shield_clicked_yes($clicked) ? 'Watch for unusual password reset or MFA notifications.' : 'Continue monitoring for repeated delivery of the same URL.',
            shield_clicked_yes($clicked) ? 'Inform IT/security if any sensitive information was submitted.' : 'Notify users not to interact with the phishing link.',
        ];
        $report['post_incident_recommendations'] = [
            'Avoid reusing passwords across multiple accounts.',
            'Access sensitive services only through official websites or bookmarks.',
            'Verify domain names carefully before entering credentials.',
            'Document indicators, affected users, timeline, and response actions.',
        ];
        $report['user_advisory'] = shield_clicked_yes($clicked)
            ? 'Do not continue interacting with this website. If any sensitive information was entered, reset the affected account immediately and report the incident to IT/security.'
            : 'Do not open this URL. Report it to IT/security; credential reset is not required unless interaction occurred.';
        $report['mitre_attack_mapping'] = shield_mitre_tag('phishing');
        $report['analyst_notes'] = 'Phishing verdict output includes full incident response guidance.';
    }

    $report['verdict_category'] = $category;
    $report['display_status'] = $displayStatus;
    $report['audience'] = $audience;
    $report['user_interaction_status'] = $interactionStatus;
    $report['model_policy'] = shield_dynamic_policy_text($category);
    $report['containment_actions'] = shield_unique_list($report['containment_actions'] ?? []);
    $report['eradication_recovery_actions'] = shield_unique_list($report['eradication_recovery_actions'] ?? []);
    $report['post_incident_recommendations'] = shield_unique_list($report['post_incident_recommendations'] ?? []);
    $report['mitre_attack_mapping'] = shield_unique_raw_list($report['mitre_attack_mapping'] ?? []);
    $report['generated_by'] = $report['generated_by'] ?? 'shieldurl:verdict-aware';
    return $report;
}

function shield_apply_verdict_report(&$analysis, $row = [], $existingReport = [], $audience = 'user')
{
    $context = [
        'url' => $analysis['url'] ?? ($row['url'] ?? ''),
        'status' => $analysis['status'] ?? ($row['status'] ?? ''),
        'display_status' => $analysis['display_status'] ?? ($analysis['overall']['display_verdict'] ?? ($row['display_status'] ?? ($row['status'] ?? ''))),
        'risk_level' => $analysis['risk_level'] ?? ($analysis['overall']['risk_level'] ?? ($row['risk_level'] ?? 'low')),
        'confidence_score' => $analysis['confidence_score'] ?? ($row['confidence_score'] ?? 0),
        'phishing_probability' => $analysis['phishing_probability'] ?? ($analysis['ml']['phishing_probability'] ?? ($row['confidence_score'] ?? 0)),
        'selected_threshold' => $analysis['selected_threshold'] ?? ($analysis['ml']['selected_threshold'] ?? ($analysis['detection']['lexical_threshold'] ?? 0.5)),
        'clicked' => $analysis['clicked'] ?? null,
    ];
    $category = shield_verdict_category($context['status'], $context['display_status'], $context['risk_level'], $context['phishing_probability'], $context['selected_threshold']);
    $context['display_status'] = shield_display_status($category, $context['display_status']);
    $context['phishing_probability'] = shield_unit_probability($context['phishing_probability']);
    $report = shield_build_verdict_report($context, $existingReport, $audience);

    $analysis['status'] = $category === 'phishing' ? 'phishing' : ($category === 'suspicious' ? 'suspicious' : 'safe');
    $analysis['display_status'] = $context['display_status'];
    $analysis['risk_level'] = $report['incident_details']['risk_level'];
    $analysis['confidence_score'] = $context['phishing_probability'];
    $analysis['phishing_probability'] = $context['phishing_probability'];
    $analysis['selected_threshold'] = shield_unit_probability($context['selected_threshold']);
    $analysis['llm_report'] = $report;
    $analysis['llm'] = $report;
    $analysis['llm_summary'] = $report['incident_summary'];
    $analysis['mitre_techniques'] = $report['mitre_attack_mapping'];
    $analysis['nist_response'] = $report['containment_actions'];
    $analysis['incident_response'] = $report['eradication_recovery_actions'];
    $analysis['post_incident_recommendations'] = $report['post_incident_recommendations'];
    $analysis['user_advisory'] = $report['user_advisory'];
    $analysis['user_interaction_status'] = $report['user_interaction_status'];
    $analysis['report_audience'] = $report['audience'];
    $analysis['model_policy'] = $report['model_policy'];
    $analysis['llm_pending'] = false;
    return $report;
}

function shield_feature_truthy($value)
{
    if (is_bool($value)) {
        return $value;
    }
    if (is_numeric($value)) {
        return (float)$value < 0;
    }
    return in_array(strtolower(shield_text($value)), ['detected', 'yes', 'true', 'suspicious', 'long'], true);
}

function shield_detection_evidence($url, $features)
{
    $url = shield_text($url);
    $features = is_array($features) ? $features : [];
    $parts = parse_url($url);
    if (empty($parts['host'])) {
        $parts = parse_url('http://' . $url);
    }
    $protocol = strtolower($parts['scheme'] ?? '');
    $host = strtolower($parts['host'] ?? '');
    $hostParts = $host !== '' ? explode('.', $host) : [];
    $tld = count($hostParts) > 1 ? end($hostParts) : '';
    $badges = [];
    $suspiciousTlds = ['zip', 'mov', 'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'icu', 'click', 'work'];
    $brandTerms = ['login', 'verify', 'secure', 'account', 'update', 'signin', 'wallet', 'bank', 'payment'];

    if ($protocol !== '' && $protocol !== 'https') {
        $badges[] = 'Non-HTTPS';
    }
    if ($tld !== '' && in_array($tld, $suspiciousTlds, true)) {
        $badges[] = 'Suspicious TLD';
    }
    $longFeature = null;
    foreach (['LongURL', 'URLURL_Length', 'URL_Length', 'url_length'] as $key) {
        if (array_key_exists($key, $features)) {
            $longFeature = $features[$key];
            break;
        }
    }
    $longByFeature = is_numeric($longFeature) ? ((float)$longFeature > 75 || (float)$longFeature < 0) : shield_feature_truthy($longFeature);
    if (strlen($url) > 75 || $longByFeature) {
        $badges[] = 'Long URL';
    }
    $lowerUrl = strtolower($url);
    foreach ($brandTerms as $term) {
        if (strpos($lowerUrl, $term) !== false) {
            $badges[] = 'Possible Brand Impersonation';
            break;
        }
    }
    return array_values(array_unique($badges));
}

?>
