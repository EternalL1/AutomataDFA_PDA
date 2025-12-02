import React, { useState } from "react";
import {
  Play,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Code2,
  RotateCcw,
} from "lucide-react";

const UnifiedWAF = () => {
  const [input, setInput] = useState("http://www.P4YPAL-S3CUR3.com/l0g1n");
  const [results, setResults] = useState(null);
  const [showCpp, setShowCpp] = useState(false);

  const analyzePacket = (content) => {
    const normalizeChar = (c) => {
      c = c.toLowerCase();
      const map = {
        0: "o",
        1: "l",
        "!": "i",
        "@": "a",
        4: "a",
        $: "s",
        5: "s",
        3: "e",
        7: "t",
      };
      return map[c] || c;
    };

    const stack = [];
    let structureValid = true;
    const pdaLogs = [];

    const patterns = [
      "paypal",
      "secure",
      "login",
      "bank",
      "select",
      "union",
      "script",
      "admin",
    ];
    const dfaLogs = [];
    let malwareFound = false;

    for (let i = 0; i < content.length; i++) {
      const rawChar = content[i];
      const normChar = normalizeChar(rawChar);

      if (structureValid) {
        if (rawChar === "<" || rawChar === "{" || rawChar === "(") {
          stack.push(rawChar);
          pdaLogs.push({
            index: i,
            char: rawChar,
            action: `Push '${rawChar}' onto stack`,
            stack: [...stack],
            valid: true,
          });
        } else if (rawChar === ">" || rawChar === "}" || rawChar === ")") {
          if (stack.length === 0) {
            pdaLogs.push({
              index: i,
              char: rawChar,
              action: `🚨 Injection Suspected: Unexpected closing '${rawChar}'`,
              stack: [...stack],
              valid: false,
            });
            structureValid = false;
          } else {
            const top = stack[stack.length - 1];
            const match =
              (rawChar === ">" && top === "<") ||
              (rawChar === "}" && top === "{") ||
              (rawChar === ")" && top === "(");

            if (match) {
              stack.pop();
              pdaLogs.push({
                index: i,
                char: rawChar,
                action: `Pop '${top}' - Match found`,
                stack: [...stack],
                valid: true,
              });
            } else {
              pdaLogs.push({
                index: i,
                char: rawChar,
                action: `🚨 Syntax Error: Mismatched '${top}' vs '${rawChar}'`,
                stack: [...stack],
                valid: false,
              });
              structureValid = false;
            }
          }
        }
      }

      const normalizedContent = content
        .substring(0, i + 1)
        .split("")
        .map(normalizeChar)
        .join("");
      for (const pattern of patterns) {
        if (normalizedContent.endsWith(pattern)) {
          const matchStart = i - pattern.length + 1;
          const snippet = content.substring(matchStart, i + 1);
          dfaLogs.push({
            index: i,
            pattern: pattern,
            snippet: snippet,
            action: `🚨 Phishing Pattern: '${snippet}' (Normalized: ${pattern})`,
          });
          malwareFound = true;
          break;
        }
      }
    }

    if (structureValid && stack.length > 0) {
      pdaLogs.push({
        index: content.length,
        char: "EOF",
        action: `🚨 Truncated Request: Unclosed tag '${
          stack[stack.length - 1]
        }'`,
        stack: [...stack],
        valid: false,
      });
      structureValid = false;
    }

    let decision, reason;
    if (!structureValid) {
      decision = "BLOCKED";
      reason = "Malformed/Injection";
    } else if (malwareFound) {
      decision = "BLOCKED";
      reason = "Phishing Signature";
    } else {
      decision = "ALLOWED";
      reason = "Clean";
    }

    return {
      content,
      pdaLogs,
      dfaLogs,
      structureValid,
      malwareFound,
      finalStack: stack,
      decision,
      reason,
    };
  };

  const handleAnalyze = () => {
    const result = analyzePacket(input);
    setResults(result);
  };

  const handleReset = () => {
    setInput("");
    setResults(null);
  };

  const testCases = [
    {
      id: "URL_01",
      label: "Leet-Speak Phishing",
      url: "http://www.P4YPAL-S3CUR3.com/l0g1n",
    },
    {
      id: "URL_02",
      label: "SQL Injection (Balanced)",
      url: "http://site.com/search?q=(SELECT * FROM users)",
    },
    {
      id: "URL_03",
      label: "SQL Injection (Broken)",
      url: "http://site.com/id=5) OR 1=1",
    },
    {
      id: "URL_04",
      label: "XSS Attack",
      url: "http://site.com/comment?msg=<script>alert(1)</script>",
    },
    {
      id: "URL_05",
      label: "Safe URL",
      url: "http://www.google.com/search?q=hello+world",
    },
  ];

  const cppCode = `// Unified Firewall Engine - C++ Backend Logic

// SINGLE PASS LOOP - Runs PDA and DFA in PARALLEL
for (int i = 0; i < content.length(); i++) {
    char rawChar = content[i];              // For PDA (Protocol)
    char normChar = normalizeChar(rawChar); // For DFA (Phishing)

    // LOGIC A: PROTOCOL VALIDATION (PDA / Type 2)
    if (rawChar == '<' || rawChar == '{' || rawChar == '(') {
        protoStack.push(rawChar); 
    }
    else if (rawChar == '>' || rawChar == '}' || rawChar == ')') {
        // Check matching brackets/tags
        // Production Rule: S -> <s>S | {s}S | (s)S | ε
    }

    // LOGIC B: PATTERN MATCHING (DFA / Type 3)
    // Aho-Corasick automaton traversal
    // Production Rule: S -> rA, A -> oB, B -> oC, C -> t
    while (currentDFA != root && !currentDFA->children[idx])
        currentDFA = currentDFA->failureLink;
}`;

  return (
    <div className="app-container">
      <div className="main-card">
        {/* Header */}
        <div className="header">
          <div className="header-content">
            <Shield className="header-icon" size={48} />
            <div>
              <h1 className="header-title">Unified WAF Simulator</h1>
              <p className="header-subtitle">
                PDA×DFA Engine | C++ Backend Logic
              </p>
            </div>
          </div>
          <button
            onClick={() => setShowCpp(!showCpp)}
            className="btn-secondary"
          >
            <Code2 size={20} />
            {showCpp ? "Hide" : "Show"} C++ Code
          </button>
        </div>

        {/* C++ Code Display */}
        {showCpp && (
          <div className="code-block">
            <pre>{cppCode}</pre>
          </div>
        )}

        {/* Input Section */}
        <div className="input-section">
          <label className="input-label">Packet Content (URL/Payload):</label>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="input-field"
            rows={3}
            placeholder="Enter URL or packet content..."
          />
        </div>

        {/* Action Buttons */}
        <div className="button-group">
          <button onClick={handleAnalyze} className="btn-primary">
            <Play size={20} />
            Analyze Packet
          </button>
          <button onClick={handleReset} className="btn-reset">
            <RotateCcw size={20} />
            Reset
          </button>
        </div>

        {/* Results Section */}
        {results && (
          <div className="results-container">
            {/* Final Decision */}
            <div
              className={`decision-card ${
                results.decision === "ALLOWED"
                  ? "decision-allowed"
                  : "decision-blocked"
              }`}
            >
              <div className="decision-content">
                {results.decision === "ALLOWED" ? (
                  <CheckCircle className="decision-icon-allowed" size={48} />
                ) : (
                  <XCircle className="decision-icon-blocked" size={48} />
                )}
                <div>
                  <h3 className="decision-title">RESULT: {results.decision}</h3>
                  <p className="decision-reason">{results.reason}</p>
                </div>
              </div>
            </div>

            {/* PDA Analysis */}
            <div className="analysis-card pda-card">
              <h3 className="analysis-title">
                <span className="title-icon">🔧</span>
                PDA State (Protocol Validation - Type 2)
              </h3>
              <div className="log-container">
                {results.pdaLogs.length > 0 ? (
                  results.pdaLogs.map((log, idx) => (
                    <div
                      key={idx}
                      className={`log-item ${log.valid ? "" : "log-error"}`}
                    >
                      <div className="log-content">
                        <div>
                          <span className="log-index">Index {log.index}: </span>
                          <span className="log-char">'{log.char}'</span>
                          <div className="log-action">{log.action}</div>
                        </div>
                        <div className="log-stack">
                          <span className="stack-label">Stack: </span>
                          <span className="stack-value">
                            [{log.stack.join(", ")}]
                          </span>
                        </div>
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="no-logs">No brackets/tags to validate</p>
                )}
              </div>
              <div className="final-stack">
                <span className="stack-label">Final Stack: </span>
                <span className="stack-value">
                  [{results.finalStack.join(", ") || "Empty ✓"}]
                </span>
                {results.structureValid ? (
                  <span className="status-valid">✓ Valid</span>
                ) : (
                  <span className="status-invalid">✗ Invalid</span>
                )}
              </div>
            </div>

            {/* DFA Analysis */}
            <div className="analysis-card dfa-card">
              <h3 className="analysis-title">
                <span className="title-icon">🛡️</span>
                DFA State (Pattern Matching - Type 3)
              </h3>
              <div className="log-container">
                {results.dfaLogs.length > 0 ? (
                  results.dfaLogs.map((log, idx) => (
                    <div key={idx} className="log-item log-threat">
                      <div className="threat-action">{log.action}</div>
                      <div className="threat-details">
                        Position: {log.index} | Snippet:
                        <span className="threat-snippet">"{log.snippet}"</span>
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="no-threats">✓ No malicious patterns detected</p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Test Cases */}
        <div className="test-cases">
          <h4 className="test-cases-title">Test Cases (from main()):</h4>
          <div className="test-cases-grid">
            {testCases.map((test) => (
              <button
                key={test.id}
                onClick={() => setInput(test.url)}
                className="test-case-btn"
              >
                <div className="test-case-id">{test.id}</div>
                <div className="test-case-label">{test.label}</div>
                <div className="test-case-url">{test.url}</div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default UnifiedWAF;
