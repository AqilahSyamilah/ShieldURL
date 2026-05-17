                    <div class="card" id="check-url">
                        <h2>Check URL Safety</h2>
                        <p class="scan-helper">Paste a URL to check whether it may be safe, suspicious, or phishing.</p>
                        <div class="shield-status">
                            <div class="shield-ring"></div>
                            <div class="shield-visual">
                                <div class="shield-scan"></div>
                                <div class="shield-burst"></div>
                                <div class="shield-label" id="shieldLabel">SCAN</div>
                            </div>
                            <div class="shield-copy">
                                <h3 id="shieldTitle">Shield standing by</h3>
                                <p id="shieldSubtitle">Run a scan to lock the protection state and color.</p>
                            </div>
                        </div>
                        <form id="checkUrlForm" class="check-form">
                            <div class="form-group">
                                <label for="url">Enter URL to Check</label>
                                <div class="form-row">
                                    <input type="url" id="url" name="url" placeholder="https://example.com" required>
                                    <button type="submit" class="btn-check" id="scanActionBtn">Scan URL</button>
                                </div>
                                <div class="trust-indicators">
                                    <span class="trust-chip">ML-based detection</span>
                                    <span class="trust-chip">LLM-assisted explanation</span>
                                    <span class="trust-chip">NIST-aligned response</span>
                                </div>
                            </div>
                            <div id="checkResult" class="result-message"></div>
                        </form>
                        <dialog id="clickedUrlModal">
                            <div style="padding: 1.25rem 1.25rem 1rem;">
                                <h3 style="margin: 0 0 0.5rem;">Security Confirmation</h3>
                                <p style="margin: 0 0 1rem; color: #4a5568;">Have you already clicked this URL?</p>
                                <div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
                                    <button type="button" class="btn-check" id="clickedYesBtn">Yes, I clicked it</button>
                                    <button type="button" class="btn-check" id="clickedNoBtn" style="background: #4a5568;">No, I did not click it</button>
                                </div>
                            </div>
                        </dialog>

                        <div id="analysisResult" class="analysis-result">
                            <div class="analysis-layout">
                                <div>
                                    <div class="dashboard-card fade-card">
                                        <div class="summary-grid">
                                            <div class="summary-card">
                                                <div class="summary-label">URL Status</div>
                                                <div class="summary-value"><span id="statusBadge" class="badge"></span></div>
                                            </div>
                                            <div class="summary-card">
                                                <div class="summary-label">Confidence Score</div>
                                                <div class="summary-value large" id="confidenceScore">0%</div>
                                                <div class="confidence-bar">
                                                    <div id="confidenceFill" class="confidence-fill" style="width: 0%"></div>
                                                </div>
                                            </div>
                                            <div class="summary-card">
                                                <div class="summary-label">Risk Level</div>
                                                <div class="summary-value" id="riskLevelValue">-</div>
                                            </div>
                                            <div class="summary-card">
                                                <div class="summary-label">MITRE Technique</div>
                                                <div class="summary-value" id="mitrePrimaryValue">-</div>
                                            </div>
                                        </div>
                                        <div class="result-field" style="margin-bottom: 0;">
                                            <label>Checked URL</label>
                                            <div class="result-value">
                                                <a id="resultUrl" href="#" target="_blank" style="word-break: break-all;">Loading...</a>
                                            </div>
                                        </div>
                                    </div>

                                    <div class="dashboard-card fade-card" style="margin-top: 0.9rem;">
                                        <label style="margin-bottom: 0.5rem;">Incident Summary</label>
                                        <p class="incident-text" id="llmSummary">-</p>
                                    </div>

                                    <div class="dashboard-card fade-card" style="margin-top: 0.9rem;">
                                        <label style="margin-bottom: 0.6rem;">Recommended Actions</label>
                                        <div class="action-grid">
                                            <div class="action-card">
                                                <h4>Containment</h4>
                                                <ul id="containmentList"></ul>
                                            </div>
                                            <div class="action-card">
                                                <h4>Eradication & Recovery</h4>
                                                <ul id="eradicationList"></ul>
                                            </div>
                                            <div class="action-card">
                                                <h4>Post-Incident Recommendations</h4>
                                                <ul id="postIncidentList"></ul>
                                            </div>
                                            <div class="action-card">
                                                <h4>User Advisory</h4>
                                                <ul id="userAdvisoryList">
                                                    <li id="userAdvisory">-</li>
                                                </ul>
                                            </div>
                                        </div>
                                        <div id="nistResponseField" style="display: none; margin-top: 0.8rem;">
                                            <label>NIST Response</label>
                                            <ul id="nistSteps" style="padding-left: 20px; line-height: 1.6;"></ul>
                                        </div>
                                        <div id="recommendedActionsField" style="display:none;">
                                            <ul id="irSteps"></ul>
                                        </div>
                                    </div>

                                    <div class="dashboard-card fade-card" style="margin-top: 0.9rem;">
                                        <label>Technical Analysis Details</label>
                                        <details class="technical-details" id="technicalDetailsPanel">
                                            <summary>Show technical details</summary>
                                            <div class="technical-json" id="analysisDetails">Loading...</div>
                                        </details>
                                        <div class="result-field" style="margin-top: 0.9rem; margin-bottom: 0;">
                                            <label>MITRE ATT&CK Tags</label>
                                            <div id="mitreTags" style="display: flex; gap: 10px; flex-wrap: wrap;"></div>
                                        </div>
                                    </div>

                                    <div class="dashboard-card fade-card result-meta">
                                        <div>
                                            <label>Analyzed At</label>
                                            <div class="result-value" id="analyzedTime">-</div>
                                        </div>
                                        <div>
                                            <a id="downloadReportBtn" href="#" target="_blank" class="btn-check download-report-btn">
                                                <span id="downloadReportLabel">Download Report</span>
                                            </a>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="assistant-column" id="assistantColumn">
                            <div class="assistant-overlay" id="assistantOverlay" aria-hidden="true"></div>
                            <div class="assistant-panel fade-card" id="assistantPanel" role="dialog" aria-modal="true" aria-labelledby="assistantPanelTitle">
                                <div class="assistant-header">
                                    <button type="button" class="assistant-close-btn" id="assistantCloseBtn" aria-label="Close ShieldURL Assistant">&times;</button>
                                    <div class="assistant-header-icon" aria-hidden="true">
                                        <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false">
                                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"></path>
                                            <path d="M8.5 10.5h7"></path>
                                            <path d="M8.5 14h4"></path>
                                        </svg>
                                    </div>
                                    <div class="assistant-header-copy">
                                        <h3 id="assistantPanelTitle">ShieldURL Assistant</h3>
                                        <span class="assistant-online-badge">Online</span>
                                    </div>
                                </div>
                                <div class="assistant-body">
                                    <div class="assistant-starters">
                                        <button type="button" class="assistant-starter">Why is this URL dangerous?</button>
                                        <button type="button" class="assistant-starter">What should I do if I clicked it?</button>
                                        <button type="button" class="assistant-starter">Explain the confidence score</button>
                                        <button type="button" class="assistant-starter">What should IT admin do?</button>
                                    </div>
                                    <div class="assistant-messages" id="assistantMessages">
                                        <div class="assistant-message notice">Please scan a URL first before using the assistant.</div>
                                    </div>
                                </div>
                                <form class="assistant-form assistant-input" id="assistantForm">
                                    <input type="text" id="assistantInput" maxlength="500" placeholder="Ask about this URL scan result..." disabled>
                                    <button type="submit" class="assistant-send" id="assistantSendBtn" disabled>Send</button>
                                </form>
                            </div>
                        </div>
                        <button id="assistantToggleBtn" type="button" class="assistant-toggle-btn floating-assistant-icon" style="display: none;" title="Open ShieldURL Assistant" aria-label="Open ShieldURL Assistant">
                            <span class="toggle-icon" aria-hidden="true">
                                <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false">
                                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"></path>
                                    <path d="M8.5 10.5h7"></path>
                                    <path d="M8.5 14h4"></path>
                                </svg>
                            </span>
                            <span id="assistantToggleLabel" class="sr-only">Open ShieldURL Assistant</span>
                        </button>
                    </div>
